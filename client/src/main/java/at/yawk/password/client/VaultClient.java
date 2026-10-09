package at.yawk.password.client;

import at.yawk.password.AuthProtocol;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.OtpBlob;
import at.yawk.password.model.PasswordBlob;
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
 * @param <T> The data of the vault, {@link PasswordBlob} or {@link OtpBlob}
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
    private boolean loaded;
    /**
     * {@code false} if the last {@link #load} found the server without registration, so that {@link #save} registers
     * {@link #keys} first. It is only registered on save, never on load: that would claim a server just because its
     * URL was entered.
     */
    private boolean registered = true;
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

    DatabaseClient getDatabaseClient() {
        return databaseClient;
    }

    public ClientValue<T> load() throws Exception {
        byte[] local = localStorage.load();

        byte[] remote;
        try {
            byte[] installSalt = databaseClient.getInstallSalt();
            if (installSalt == null) {
                registered = false;
                // the keys of the local copy, or new ones for a new database
                byte[] localSalt = local == null ? null : BlobCodec.installSalt(local);
                if (localSalt != null) {
                    keys = keysFor(localSalt);
                } else if (!key.mayRegister()) {
                    throw new WrongPasswordException(RESET_MESSAGE);
                } else if (keys == null || !keysFromServer) {
                    keys = key.keysForNewVault();
                }
                keysFromServer = true;
                remote = null;
            } else {
                registered = true;
                keys = keysFor(installSalt);
                keysFromServer = true;
                try {
                    remote = databaseClient.getDatabase(keys);
                } catch (FileNotFoundException e) {
                    remote = null;
                }
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
                return new ClientValue<>(null, ClientValue.LocalReason.NOT_ON_SERVER);
            }
            return loaded(decryptLocal(local), ClientValue.LocalReason.NOT_ON_SERVER);
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

    @SuppressWarnings("unchecked")
    private DecryptedBlob<T> decryptLocal(byte[] local) throws Exception {
        byte[] localSalt = BlobCodec.installSalt(local);
        if (localSalt != null) {
            return BlobCodec.decrypt(objectMapper, keysFor(localSalt), local, dataClass);
        } else if (dataClass == PasswordBlob.class && key.getPassword() != null && LegacyBlob.isLegacy(local)) {
            // only the password vault existed in the old format
            log.info("Local copy is in the legacy format, it will be migrated on the next save");
            return (DecryptedBlob<T>) LegacyBlob.decrypt(objectMapper, key.getPassword(), local);
        } else {
            throw new Exception("Invalid database: unknown format");
        }
    }

    private KeyMaterial keysFor(byte[] installSalt) throws WrongPasswordException {
        return key.keysFor(installSalt);
    }

    /**
     * Save the database locally, then upload it. Registers the server first if {@link #load} found it without
     * registration.
     *
     * @throws IllegalStateException if nothing was loaded yet
     */
    public void save(T blob) throws Exception {
        if (!loaded) {
            throw new IllegalStateException("Load the database before saving");
        }
        KeyMaterial keys = this.keys;
        if (keys == null) {
            throw new IOException("The server was unreachable, and the local copy is in the old format. Reload once " +
                                  "the server is reachable, then save to migrate it.");
        }
        if (!registered && !key.mayRegister()) {
            throw new WrongPasswordException(RESET_MESSAGE);
        }
        DecryptedBlob<T> decrypted = new DecryptedBlob<>();
        decrypted.setData(blob);
        decrypted.setRevision(revision + 1);
        byte[] encrypted = BlobCodec.encrypt(objectMapper, keys, decrypted);
        localStorage.save(encrypted);
        revision = decrypted.getRevision();

        if (!registered) {
            databaseClient.register(keys);
            registered = true;
        }
        databaseClient.putDatabase(keys, encrypted);
    }

    /**
     * Export the key that {@link #save} uses, for {@link VaultKey#ofExportedKey}: the install salt and root key. It
     * opens this vault like the password does, so keep it as safe as the data.
     *
     * @return {@link VaultKey#EXPORTED_LENGTH} bytes, to be wiped by the caller
     * @throws IllegalStateException unless the last load or save used the keys of the server's registration: an
     * export before the first save of a new vault, or while the server is unreachable, could give a key that the server
     * never accepts
     */
    public byte[] exportKey() {
        KeyMaterial keys = this.keys;
        if (!loaded || keys == null || !registered || !keysFromServer) {
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
