package at.yawk.password.server;

import at.yawk.password.FileLocalStorageProvider;
import at.yawk.password.HashUtil;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.MultiFileLocalStorageProvider;
import at.yawk.password.PlatformDependent;
import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.Property;
import io.micronaut.core.annotation.Nullable;
import jakarta.inject.Inject;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import net.jodah.expiringmap.ExpirationPolicy;
import net.jodah.expiringmap.ExpiringMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Server state: the stored database and shared secret, and the outstanding challenge tokens.
 *
 * <p>Eagerly created ({@link Context}) so that problems with the data directory show up at startup rather than on the
 * first request.
 *
 * @author yawkat
 */
@Context
public class DatabaseState {
    /**
     * Directory holding the database versions and the shared secret.
     */
    public static final String DATA_DIR_PROPERTY = "password.data-dir";

    /**
     * Upper bound on outstanding challenge tokens. /challenge is unauthenticated, so without a bound a client could
     * grow the heap until entries expire. When full, the oldest challenge is evicted, so under a flood a legitimate
     * client whose challenge was evicted gets a 403 on /db and has to retry. This trades unbounded memory growth for
     * a temporary authentication failure.
     */
    static final int MAX_OUTSTANDING_CHALLENGES = 10_000;

    private static final Logger log = LoggerFactory.getLogger(DatabaseState.class);

    private final LocalStorageProvider databaseStorageProvider;
    private final LocalStorageProvider sharedSecretStorageProvider;
    private final Set<ByteArrayWrapper> tokens = createTokenSet();

    @Inject
    DatabaseState(@Property(name = DATA_DIR_PROPERTY, defaultValue = ".") String dataDirectory) throws IOException {
        File dir = new File(dataDirectory);
        warnIfAccessibleByOthers(dir.toPath());

        FileLocalStorageProvider sharedSecretStorageProvider =
                new FileLocalStorageProvider(new File(dir, "shared-secret"));
        sharedSecretStorageProvider.restrictPermissions();

        this.databaseStorageProvider = new MultiFileLocalStorageProvider(dir);
        this.sharedSecretStorageProvider = sharedSecretStorageProvider;
    }

    static <T> Set<T> createTokenSet() {
        return Collections.newSetFromMap(
                ExpiringMap.builder()
                        .expiration(1, TimeUnit.MINUTES)
                        .expirationPolicy(ExpirationPolicy.CREATED)
                        .maxSize(MAX_OUTSTANDING_CHALLENGES)
                        .build());
    }

    private static void warnIfAccessibleByOthers(Path dir) {
        if (!Files.isDirectory(dir) || !PlatformDependent.isPosix(dir)) {
            return;
        }
        Set<PosixFilePermission> perms;
        try {
            perms = Files.getPosixFilePermissions(dir);
        } catch (IOException e) {
            // only a warning, never fail startup
            return;
        }
        if (!perms.stream().allMatch(p -> p.name().startsWith("OWNER_"))) {
            log.warn("Data directory {} is accessible by other users ({}), consider chmod 700",
                     dir.toAbsolutePath(), PosixFilePermissions.toString(perms));
        }
    }

    /**
     * Create a new single-use challenge and remember the token that answers it.
     *
     * @return The challenge, or {@code null} if no shared secret has been set yet.
     */
    @Nullable
    byte[] createChallenge() throws IOException {
        byte[] sharedSecret = sharedSecretStorageProvider.load();
        if (sharedSecret == null) {
            return null;
        }

        byte[] challenge = HashUtil.generateRandomBytes(32);

        byte[] token = HashUtil.sha512(sharedSecret, challenge);
        tokens.add(new ByteArrayWrapper(token));

        return challenge;
    }

    boolean isSharedSecretSet() throws IOException {
        return sharedSecretStorageProvider.load() != null;
    }

    /**
     * Set the shared secret, unless one is already set.
     *
     * @return {@code false} if a shared secret was already set, in which case it is left unchanged.
     */
    synchronized boolean setSharedSecretIfUnset(byte[] secret) throws IOException {
        if (isSharedSecretSet()) {
            return false;
        }
        sharedSecretStorageProvider.save(secret);
        return true;
    }

    /**
     * Consume the challenge token given in the {@code X-Auth-Token} header.
     *
     * @return {@code true} if the token was valid. A token can only be used once.
     */
    boolean takeToken(@Nullable String header) {
        byte[] token = parseToken(header);
        return token != null && tokens.remove(new ByteArrayWrapper(token));
    }

    /**
     * Parse the client-supplied hex token, returning {@code null} if it is missing or malformed.
     */
    @Nullable
    static byte[] parseToken(@Nullable String header) {
        if (header == null) {
            return null;
        }
        try {
            return HexFormat.of().parseHex(header);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    @Nullable
    byte[] loadDatabase() throws IOException {
        return databaseStorageProvider.load();
    }

    void saveDatabase(byte[] db) throws IOException {
        databaseStorageProvider.save(db);
    }

    private record ByteArrayWrapper(byte[] array) {
        @Override
        public boolean equals(Object o) {
            return o instanceof ByteArrayWrapper other && Arrays.equals(array, other.array);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(array);
        }
    }
}
