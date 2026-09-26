package at.yawk.password.client;

import at.yawk.password.AuthProtocol;
import at.yawk.password.HashUtil;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.PasswordBlob;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Nullable;

/**
 * Loads and saves the database: remote first, with the local copy as a fallback. See SPEC.md, "Client behaviour".
 *
 * <p>Not thread safe on its own; {@link PasswordStore} serializes the calls.
 *
 * @author yawkat
 */
@Slf4j
public class PasswordClient {
    private final DatabaseClient databaseClient;
    private final LocalStorageProvider localStorage;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final byte[] password;

    /**
     * Keys derived so far, by install salt. Usually only the server's; a local copy written for another registration
     * (or none yet) adds one.
     */
    private final List<KeyMaterial> derivedKeys = new ArrayList<>();
    /**
     * The keys that {@link #save} encrypts and signs with, chosen by {@link #load}.
     */
    @Nullable private KeyMaterial keys;
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

    public PasswordClient(String url, LocalStorageProvider localStorage, byte[] password) {
        this.databaseClient = new DatabaseClient(url);
        this.localStorage = localStorage;
        this.password = password;
    }

    DatabaseClient getDatabaseClient() {
        return databaseClient;
    }

    public ClientValue<PasswordBlob> load() throws Exception {
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
                } else if (keys == null) {
                    keys = keysFor(HashUtil.generateRandomBytes(AuthProtocol.SALT_LENGTH));
                }
                remote = null;
            } else {
                registered = true;
                keys = keysFor(installSalt);
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
            // the server state is unknown: keep writing with the keys of the local copy, but don't register
            registered = true;
            byte[] localSalt = BlobCodec.installSalt(local);
            if (localSalt != null) {
                keys = keysFor(localSalt);
            } else if (keys == null) {
                keys = keysFor(HashUtil.generateRandomBytes(AuthProtocol.SALT_LENGTH));
            }
            return loaded(decryptLocal(local), ClientValue.LocalReason.SERVER_UNAVAILABLE);
        }

        if (remote == null) {
            if (local == null) {
                revision = 0;
                return new ClientValue<>(null, ClientValue.LocalReason.NOT_ON_SERVER);
            }
            return loaded(decryptLocal(local), ClientValue.LocalReason.NOT_ON_SERVER);
        }

        DecryptedBlob remoteBlob;
        try {
            remoteBlob = BlobCodec.decrypt(objectMapper, keys, remote);
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
            DecryptedBlob localBlob = null;
            try {
                localBlob = BlobCodec.decrypt(objectMapper, keys, local);
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

    private ClientValue<PasswordBlob> loaded(DecryptedBlob blob, @Nullable ClientValue.LocalReason reason) {
        revision = blob.getRevision();
        return new ClientValue<>(blob.getData(), reason);
    }

    private DecryptedBlob decryptLocal(byte[] local) throws Exception {
        byte[] localSalt = BlobCodec.installSalt(local);
        if (localSalt != null) {
            return BlobCodec.decrypt(objectMapper, keysFor(localSalt), local);
        } else if (LegacyBlob.isLegacy(local)) {
            log.info("Local copy is in the legacy format, it will be migrated on the next save");
            return LegacyBlob.decrypt(objectMapper, password, local);
        } else {
            throw new Exception("Invalid database: unknown format");
        }
    }

    private KeyMaterial keysFor(byte[] installSalt) {
        for (KeyMaterial derived : derivedKeys) {
            if (derived.hasInstallSalt(installSalt)) {
                return derived;
            }
        }
        KeyMaterial derived = KeyMaterial.derive(password, installSalt);
        derivedKeys.add(derived);
        return derived;
    }

    /**
     * Save the database locally, then upload it. Registers the server first if {@link #load} found it without
     * registration.
     *
     * @throws IllegalStateException if nothing was loaded yet
     */
    public void save(PasswordBlob blob) throws Exception {
        KeyMaterial keys = this.keys;
        if (keys == null) {
            throw new IllegalStateException("Load the database before saving");
        }
        DecryptedBlob decrypted = new DecryptedBlob();
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
}
