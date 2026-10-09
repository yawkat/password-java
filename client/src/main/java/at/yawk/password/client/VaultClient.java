package at.yawk.password.client;

import at.yawk.password.AuthProtocol;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.OtpBlob;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Nullable;

/**
 * Loads and saves a vault: remote first, with the local copy as a fallback. See SPEC.md, "Client behaviour". The
 * password vault ({@link PasswordClient}) and the 2FA vault ({@link #otp}) work the same, with their own paths on the
 * server, keys and data.
 *
 * <p>Not thread safe on its own; {@link PasswordStore} and {@link OtpStore} serialize the calls.
 *
 * @param <T> The data of the vault, {@link at.yawk.password.model.PasswordBlob} or {@link OtpBlob}
 * @author yawkat
 */
@Slf4j
public class VaultClient<T> {
    private final DatabaseClient databaseClient;
    private final LocalStorageProvider localStorage;
    private final ObjectMapper objectMapper = new ObjectMapper();
    /**
     * Where the keys come from. Keys derived from a password are kept by install salt: usually only the server's; a
     * local copy written for another registration (or none yet) adds one.
     */
    private final VaultKey key;
    private final Class<T> dataClass;

    private static final String RESET_MESSAGE =
            "The vault was reset on the server. Unlock it with its password to create it again.";
    /**
     * The keys that {@link #save} encrypts and signs with, chosen by {@link #load}. {@code null} if nothing was loaded,
     * or if the server was unreachable and the local copy doesn't tell the install salt either (a legacy copy).
     */
    @Nullable private KeyMaterial keys;
    /**
     * Whether {@link #keys} were chosen knowing the server state: the server's install salt, or the salt to register.
     * Otherwise they are those of the local copy, assumed to be the server's.
     */
    private boolean keysFromServer;
    /**
     * Whether the server accepted {@link #keys} since the last {@link #load}: their signature on a request for the
     * database, or the registration. Only such keys are exported.
     */
    private boolean keysAccepted;
    /**
     * Whether the last {@link #load} succeeded. A failed load leaves nothing to save with, since what an earlier load
     * found may not be the server's state anymore.
     */
    private boolean loaded;
    /**
     * {@code false} if the last {@link #load} found the server without registration, so that {@link #save} registers
     * {@link #keys} first. It is only registered on save, never on load: that would claim a server just because its
     * URL was entered.
     */
    private boolean registered = true;
    /**
     * The new keys to register, while the server has no registration: kept, so that loading again doesn't derive
     * another set.
     */
    @Nullable private KeyMaterial keysToRegister;
    /**
     * Revision of the database that was loaded or saved last.
     */
    private long revision;

    /**
     * @param pathPrefix The vault's path prefix on the server: {@code ""} for the password vault, or
     * {@link AuthProtocol#TOTP_VAULT_PREFIX}
     */
    public VaultClient(String url, String pathPrefix, LocalStorageProvider localStorage, VaultKey key,
                       Class<T> dataClass) {
        this.databaseClient = new DatabaseClient(url, pathPrefix);
        this.localStorage = localStorage;
        this.key = key;
        this.dataClass = dataClass;
    }

    /**
     * A client of the 2FA vault.
     */
    public static VaultClient<OtpBlob> otp(String url, LocalStorageProvider localStorage, VaultKey key) {
        return new VaultClient<>(url, AuthProtocol.TOTP_VAULT_PREFIX, localStorage, key, OtpBlob.class);
    }

    public ClientValue<T> load() throws Exception {
        loaded = false;
        keysAccepted = false;
        byte[] local = localStorage.load();

        byte[] remote;
        ClientValue.LocalReason reasonWithoutRemote = ClientValue.LocalReason.NOT_ON_SERVER;
        try {
            byte[] installSalt = databaseClient.getInstallSalt();
            if (installSalt == null) {
                if (key.mayRegister()) {
                    // A new registration always gets a new install salt, also when it uploads the content of a local
                    // copy. A vault that was reset (e.g. to change its password, or to lock out the exported key of a
                    // lost device) must not come back with its old keys.
                    if (keysToRegister == null) {
                        keysToRegister = key.keysForNewVault();
                    }
                    keys = keysToRegister;
                } else {
                    // An exported key belongs to a registration that is gone: the vault was reset. It reads (and
                    // saves to) a local copy of its registration, but never registers, see save.
                    if (local == null) {
                        throw new WrongPasswordException(RESET_MESSAGE);
                    }
                    byte[] localSalt = BlobCodec.installSalt(local);
                    keys = localSalt == null ? null : keysFor(localSalt);
                    reasonWithoutRemote = ClientValue.LocalReason.VAULT_RESET;
                }
                registered = false;
                keysFromServer = true;
                remote = null;
            } else {
                // fails for an exported key of another registration, before anything changes
                KeyMaterial serverKeys = keysFor(installSalt);
                keys = serverKeys;
                keysToRegister = null;
                registered = true;
                keysFromServer = true;
                try {
                    remote = databaseClient.getDatabase(serverKeys);
                } catch (FileNotFoundException e) {
                    remote = null;
                }
                keysAccepted = true;
            }
        } catch (IOException e) {
            log.info("Could not get db from remote, trying local", e);
            if (local == null) {
                throw e;
            }
            DecryptedBlob<T> localBlob = decryptLocal(local);
            if (!keysFromServer) {
                // Nothing is known about the server: assume the local copy's registration, but never register. A
                // legacy copy has none, so it can only be saved once the server is reachable.
                registered = true;
                byte[] localSalt = BlobCodec.installSalt(local);
                keys = localSalt == null ? null : keysFor(localSalt);
            }
            return loaded(localBlob, ClientValue.LocalReason.SERVER_UNAVAILABLE);
        }

        if (remote == null) {
            if (local == null) {
                loaded = true;
                revision = 0;
                return new ClientValue<>(null, reasonWithoutRemote);
            }
            return loaded(decryptLocal(local), reasonWithoutRemote);
        }

        DecryptedBlob<T> remoteBlob;
        try {
            remoteBlob = BlobCodec.decrypt(objectMapper, keys, remote, dataClass);
        } catch (Exception e) {
            log.warn("Could not verify db from remote, trying local", e);
            try {
                if (local != null) {
                    return loaded(decryptLocal(local), ClientValue.LocalReason.SERVER_COPY_INVALID);
                }
            } catch (Exception localException) {
                e.addSuppressed(localException);
            }
            // rethrow remote exception
            throw e;
        }

        // Rollback check, against a local copy of the same registration only: the revisions of different
        // registrations are unrelated, and a legacy copy has none.
        if (local != null && keys.hasInstallSalt(BlobCodec.installSalt(local))) {
            DecryptedBlob<T> localBlob = null;
            try {
                localBlob = BlobCodec.decrypt(objectMapper, keys, local, dataClass);
            } catch (Exception e) {
                log.warn("Could not decrypt the local copy, replacing it with the server copy", e);
            }
            if (localBlob != null && localBlob.getRevision() > remoteBlob.getRevision()) {
                log.warn("Server copy (revision {}) is older than the local copy (revision {})",
                         remoteBlob.getRevision(), localBlob.getRevision());
                return loaded(localBlob, ClientValue.LocalReason.SERVER_COPY_OLDER);
            }
        }

        try {
            localStorage.save(remote);
        } catch (IOException e) {
            log.warn("Could not save db from remote to local storage", e);
        }
        return loaded(remoteBlob, null);
    }

    private ClientValue<T> loaded(DecryptedBlob<T> blob, @Nullable ClientValue.LocalReason reason) {
        loaded = true;
        revision = blob.getRevision();
        return new ClientValue<>(blob.getData(), reason);
    }

    private DecryptedBlob<T> decryptLocal(byte[] local) throws Exception {
        byte[] localSalt = BlobCodec.installSalt(local);
        if (localSalt != null) {
            return BlobCodec.decrypt(objectMapper, keysFor(localSalt), local, dataClass);
        }
        DecryptedBlob<T> legacy = decryptLegacy(local);
        if (legacy == null) {
            throw new Exception("Invalid database: unknown format");
        }
        return legacy;
    }

    /**
     * Decrypt a local copy in the format of the old protocol.
     *
     * @return {@code null} if this vault has no old format, or the blob is not in it
     */
    @Nullable
    DecryptedBlob<T> decryptLegacy(byte[] local) throws Exception {
        return null;
    }

    private KeyMaterial keysFor(byte[] installSalt) throws WrongPasswordException {
        return key.keysFor(installSalt);
    }

    /**
     * Save the database locally, then upload it. Registers the server first if {@link #load} found it without
     * registration.
     *
     * @throws IllegalStateException if nothing was loaded yet, or the last load failed
     * @throws WrongPasswordException if the vault was reset on the server and this client has an exported key, which
     * can't register it again (see {@link ClientValue.LocalReason#VAULT_RESET}). The local copy is saved anyway.
     */
    public void save(T blob) throws Exception {
        if (!loaded) {
            throw new IllegalStateException("Load the database before saving (the last load failed)");
        }
        KeyMaterial keys = this.keys;
        if (keys == null) {
            throw new IOException("The server was unreachable, and the local copy is in the old format. Reload once " +
                                  "the server is reachable, then save to migrate it.");
        }
        DecryptedBlob<T> decrypted = new DecryptedBlob<>();
        decrypted.setData(blob);
        decrypted.setRevision(revision + 1);
        byte[] encrypted = BlobCodec.encrypt(objectMapper, keys, decrypted);
        localStorage.save(encrypted);
        revision = decrypted.getRevision();

        if (!registered) {
            if (!key.mayRegister()) {
                throw new WrongPasswordException(RESET_MESSAGE);
            }
            databaseClient.register(keys);
            registered = true;
            keysToRegister = null;
        }
        databaseClient.putDatabase(keys, encrypted);
        keysAccepted = true;
    }

    /**
     * Export the key that {@link #save} uses, for {@link VaultKey#ofExportedKey}: the install salt and root key. It
     * opens this vault like the password does, so keep it as safe as the data.
     *
     * @return {@link VaultKey#EXPORTED_LENGTH} bytes, to be wiped by the caller
     * @throws IllegalStateException unless the server accepted the keys since the last load: an export before the first
     * save of a new vault, or while the server is unreachable or refuses the keys, could give a key that the server
     * never accepts
     */
    public byte[] exportKey() {
        KeyMaterial keys = this.keys;
        if (!keysAccepted || keys == null) {
            throw new IllegalStateException("No keys of the server's vault to export, load or save it first");
        }
        byte[] rootKey = keys.getRootKey();
        try {
            return ByteBuffer.allocate(VaultKey.EXPORTED_LENGTH).put(keys.getInstallSalt()).put(rootKey).array();
        } finally {
            Arrays.fill(rootKey, (byte) 0);
        }
    }
}
