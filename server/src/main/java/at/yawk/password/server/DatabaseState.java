package at.yawk.password.server;

import at.yawk.password.AuthProtocol;
import at.yawk.password.FileLocalStorageProvider;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.MultiFileLocalStorageProvider;
import at.yawk.password.PlatformDependent;
import io.micronaut.core.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * State of one vault (see {@link Vaults}): the stored database and registration, the nonces of recently accepted
 * requests, and the backoff after failed signatures.
 *
 * @author yawkat
 */
public class DatabaseState {

    /**
     * Upper bound on remembered nonces. Only requests with a valid signature add one, so only the owner can fill it.
     */
    static final int MAX_REMEMBERED_NONCES = 10_000;
    /**
     * How old a request may be once its body has been read and its signature is checked. Nonces are remembered for
     * as long, so a replay can't complete after the original was forgotten.
     */
    static final long MAX_REQUEST_AGE_MILLIS = 2 * AuthProtocol.MAX_CLOCK_SKEW_MILLIS;

    /**
     * Number of failed signatures in a row that are allowed before the backoff starts.
     */
    static final int FREE_FAILURES = 5;
    static final long MAX_BACKOFF_MILLIS = TimeUnit.HOURS.toMillis(1);

    /**
     * DER prefix of an X.509 Ed25519 public key, followed by the 32 raw key bytes.
     */
    private static final byte[] ED25519_X509_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");

    private static final Logger log = LoggerFactory.getLogger(DatabaseState.class);

    private final LocalStorageProvider databaseStorageProvider;
    private final FileLocalStorageProvider registrationStorageProvider;
    @Nullable private final File legacySharedSecret;
    private final File directory;
    private final NonceMemory nonces = new NonceMemory(MAX_REMEMBERED_NONCES, MAX_REQUEST_AGE_MILLIS);
    /**
     * The registration file, which never changes once written. The operator resets a server while it is stopped.
     */
    /**
     * The registration ({@link AuthProtocol#REGISTRATION_LENGTH} bytes), or {@code null} if there is none.
     */
    @Nullable private volatile byte[] registration;
    LongSupplier clock = System::currentTimeMillis;

    private int consecutiveFailures = 0;
    private long blockedUntil = 0;

    /**
     * The password vault, in the data directory itself.
     */
    DatabaseState(String dataDirectory) throws IOException {
        this(new File(dataDirectory), new File(dataDirectory, "shared-secret"));
    }

    /**
     * @param dir The vault's directory. If it doesn't exist yet, it is created (owner-only) on registration.
     * @param legacySharedSecret The shared secret of the old protocol, which only the password vault can have. It is
     * deleted on registration.
     * @throws IOException if the directory exists, but is not a directory that the server can read and write
     */
    DatabaseState(File dir, @Nullable File legacySharedSecret) throws IOException {
        this.directory = dir;
        this.legacySharedSecret = legacySharedSecret;
        if (dir.exists() && !(dir.isDirectory() && dir.canRead() && dir.canWrite() && dir.canExecute())) {
            throw new IOException(dir + " is not a directory that the server can read and write");
        }
        warnIfAccessibleByOthers(dir.toPath());

        registrationStorageProvider = new FileLocalStorageProvider(new File(dir, "verifier"));
        registrationStorageProvider.restrictPermissions();
        registration = registrationStorageProvider.load();
        if (registration != null) {
            try {
                checkRegistration(registration);
            } catch (IllegalArgumentException e) {
                throw new IOException("Invalid registration file " + new File(dir, "verifier") +
                                      ", delete it to register again", e);
            }
        }
        databaseStorageProvider = new MultiFileLocalStorageProvider(dir);

        if (legacySharedSecret != null && legacySharedSecret.exists() && registration == null) {
            log.warn("Found the shared secret of the old protocol but no registration. Migrate by unlocking with the " +
                     "new client, see the README; the old secret is deleted on registration.");
        }
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

    boolean isRegistered() {
        return registration != null;
    }

    /**
     * @return The {@code GET /salt} response, or {@code null} if there is no registration.
     */
    @Nullable
    byte[] getSaltResponse() {
        byte[] registration = this.registration;
        return registration == null ? null : Arrays.copyOf(registration, AuthProtocol.SALT_RESPONSE_LENGTH);
    }

    /**
     * Store the registration, unless there is one already.
     *
     * @return {@code false} if there was a registration already, in which case it is left unchanged.
     * @throws IllegalArgumentException if the registration is malformed
     */
    synchronized boolean registerIfUnregistered(byte[] registration) throws IOException {
        checkRegistration(registration);
        if (isRegistered()) {
            return false;
        }
        if (!directory.isDirectory()) {
            PlatformDependent.createOwnerOnlyDirectory(directory.toPath());
        }
        registrationStorageProvider.save(registration);
        this.registration = registration.clone();
        if (legacySharedSecret != null && legacySharedSecret.delete()) {
            log.info("Deleted the shared secret of the old protocol");
        }
        return true;
    }

    /**
     * @throws IllegalArgumentException if the registration is malformed
     */
    private static void checkRegistration(byte[] registration) {
        if (registration.length != AuthProtocol.REGISTRATION_LENGTH || registration[0] != AuthProtocol.VERSION) {
            throw new IllegalArgumentException("Malformed registration");
        }
        try {
            publicKey(registration);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Malformed public key", e);
        }
    }

    private static PublicKey publicKey(byte[] registration) throws GeneralSecurityException {
        byte[] encoded = Arrays.copyOf(ED25519_X509_PREFIX, ED25519_X509_PREFIX.length + AuthProtocol.PUBLIC_KEY_LENGTH);
        System.arraycopy(registration, 1 + AuthProtocol.SALT_LENGTH, encoded, ED25519_X509_PREFIX.length,
                         AuthProtocol.PUBLIC_KEY_LENGTH);
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));
    }

    /**
     * The parsed {@link AuthProtocol#AUTH_HEADER} header.
     */
    record AuthHeader(long timestamp, String nonceHex, byte[] signature) {
    }

    /**
     * Parse the header, returning {@code null} if it is missing or malformed.
     */
    @Nullable
    static AuthHeader parseAuthHeader(@Nullable String header) {
        if (header == null) {
            return null;
        }
        String[] parts = header.split(" ", -1);
        if (parts.length != 3 ||
            parts[0].isEmpty() || parts[0].length() > 19 || !parts[0].chars().allMatch(c -> c >= '0' && c <= '9') ||
            parts[1].length() != AuthProtocol.NONCE_LENGTH * 2 ||
            parts[2].length() != AuthProtocol.SIGNATURE_LENGTH * 2) {
            return null;
        }
        byte[] signature = AuthProtocol.parseHex(parts[2]);
        // the nonce must be lowercase, as signed: a change of case must not make a replay look new
        if (AuthProtocol.parseHex(parts[1]) == null || !parts[1].equals(parts[1].toLowerCase(Locale.ROOT)) ||
            signature == null) {
            return null;
        }
        try {
            return new AuthHeader(Long.parseLong(parts[0]), parts[1], signature);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    enum Verdict {
        OK,
        /**
         * Missing or malformed header, or a replayed nonce.
         */
        FORBIDDEN,
        /**
         * The timestamp is too far from the server clock: more than {@link AuthProtocol#MAX_CLOCK_SKEW_MILLIS} when
         * the request arrives, or {@link #MAX_REQUEST_AGE_MILLIS} when its body has been read.
         */
        STALE,
        /**
         * Too many failed signatures recently.
         */
        BACKOFF,
    }

    /**
     * Checks that don't need the body, so that a request can be rejected before reading it.
     */
    synchronized Verdict preCheck(@Nullable AuthHeader header) {
        return check(header, AuthProtocol.MAX_CLOCK_SKEW_MILLIS);
    }

    private Verdict check(@Nullable AuthHeader header, long maxSkew) {
        if (clock.getAsLong() < blockedUntil) {
            return Verdict.BACKOFF;
        }
        if (header == null || !isRegistered()) {
            return Verdict.FORBIDDEN;
        }
        if (Math.abs(clock.getAsLong() - header.timestamp()) > maxSkew) {
            return Verdict.STALE;
        }
        if (nonces.contains(header.nonceHex())) {
            return Verdict.FORBIDDEN;
        }
        return Verdict.OK;
    }

    /**
     * Verify the signature of a request that passed {@link #preCheck}, and remember its nonce. The checks of
     * {@link #preCheck} are repeated, e.g. for the same request twice concurrently, but reading the body may have
     * taken a while, so the timestamp may be up to {@link #MAX_REQUEST_AGE_MILLIS} old by now.
     */
    synchronized Verdict verify(AuthHeader header, String method, String path, byte[] body) {
        Verdict verdict = check(header, MAX_REQUEST_AGE_MILLIS);
        if (verdict != Verdict.OK) {
            return verdict;
        }
        byte[] registration = this.registration;
        boolean valid;
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(publicKey(registration));
            signature.update(AuthProtocol.signingInput(header.timestamp(), header.nonceHex(), method, path, body));
            valid = signature.verify(header.signature());
        } catch (GeneralSecurityException e) {
            log.warn("Could not verify the request signature", e);
            valid = false;
        }
        if (valid) {
            nonces.add(header.nonceHex(), header.timestamp(), clock.getAsLong());
            consecutiveFailures = 0;
        } else {
            consecutiveFailures++;
            if (consecutiveFailures >= FREE_FAILURES) {
                int exponent = Math.min(consecutiveFailures - FREE_FAILURES, 20);
                long backoff = Math.min(TimeUnit.SECONDS.toMillis(1L << exponent), MAX_BACKOFF_MILLIS);
                blockedUntil = clock.getAsLong() + backoff;
                log.warn("{} failed signatures in a row, refusing requests for {} s",
                         consecutiveFailures, backoff / 1000);
            }
        }
        return valid ? Verdict.OK : Verdict.FORBIDDEN;
    }

    /**
     * Check that an uploaded database has a header of the current format and our install salt, so that a buggy
     * client can't replace the database with something no client can read.
     */
    boolean isValidDatabase(byte[] db) {
        byte[] registration = this.registration;
        if (registration == null || db.length < AuthProtocol.BLOB_HEADER_LENGTH) {
            return false;
        }
        return Arrays.equals(db, 0, AuthProtocol.BLOB_MAGIC.length, AuthProtocol.BLOB_MAGIC, 0,
                             AuthProtocol.BLOB_MAGIC.length) &&
               db[AuthProtocol.BLOB_MAGIC.length] == AuthProtocol.VERSION &&
               Arrays.equals(db, AuthProtocol.BLOB_INSTALL_SALT_OFFSET,
                             AuthProtocol.BLOB_INSTALL_SALT_OFFSET + AuthProtocol.SALT_LENGTH,
                             registration, 1, 1 + AuthProtocol.SALT_LENGTH);
    }

    /**
     * @return The database, or {@code null} if there is none of this registration. The data directory may still hold
     * the database of the old protocol, which must not be served to whoever registers a migrated server first.
     */
    @Nullable
    byte[] loadDatabase() throws IOException {
        byte[] db = databaseStorageProvider.load();
        return db != null && isValidDatabase(db) ? db : null;
    }

    void saveDatabase(byte[] db) throws IOException {
        databaseStorageProvider.save(db);
    }
}
