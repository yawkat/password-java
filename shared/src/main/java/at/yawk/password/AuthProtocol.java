package at.yawk.password;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import lombok.SneakyThrows;
import org.jetbrains.annotations.Nullable;
import lombok.experimental.UtilityClass;

/**
 * Wire constants of the authentication protocol, shared by client and server. See SPEC.md.
 *
 * <p>Requests to {@code /db} carry an {@value #AUTH_HEADER} header {@code <timestamp> <nonce> <signature>}: the
 * client's clock in unix milliseconds, {@value #NONCE_LENGTH} random bytes as hex, and the hex Ed25519 signature of
 * {@link #signingInput}. There is no challenge: the timestamp bounds how long a request stays valid, and the server
 * remembers the nonces of accepted requests for that long.
 *
 * @author yawkat
 */
@UtilityClass
public class AuthProtocol {
    /**
     * The only protocol version. It selects the (hardcoded) key derivation parameters and blob format, so it is the
     * only parameter a server or a stored blob can choose.
     */
    public static final int VERSION = 1;

    public static final String AUTH_HEADER = "X-Auth";

    public static final int SALT_LENGTH = 32;
    public static final int PUBLIC_KEY_LENGTH = 32;
    public static final int SIGNATURE_LENGTH = 64;
    public static final int NONCE_LENGTH = 16;

    /**
     * {@code GET /salt} response: version byte, then the install salt.
     */
    public static final int SALT_RESPONSE_LENGTH = 1 + SALT_LENGTH;
    /**
     * {@code PUT /register} body: version byte, install salt, Ed25519 public key.
     */
    public static final int REGISTRATION_LENGTH = 1 + SALT_LENGTH + PUBLIC_KEY_LENGTH;

    /**
     * How far the request timestamp may be from the server clock.
     */
    public static final long MAX_CLOCK_SKEW_MILLIS = 60_000;

    /**
     * Header of the encrypted blob: magic, version byte, install salt, blob salt, GCM nonce. The server checks the
     * magic, version and install salt on upload.
     */
    public static final byte[] BLOB_MAGIC = { 'P', 'W', 'D', 'B' };
    public static final int BLOB_SALT_LENGTH = 32;
    public static final int BLOB_NONCE_LENGTH = 12;
    public static final int BLOB_HEADER_LENGTH =
            BLOB_MAGIC.length + 1 + SALT_LENGTH + BLOB_SALT_LENGTH + BLOB_NONCE_LENGTH;
    public static final int BLOB_INSTALL_SALT_OFFSET = BLOB_MAGIC.length + 1;

    /**
     * The message that the {@value #AUTH_HEADER} signature covers. It is text, so that it can be built with shell
     * tools; none of the fields can contain a newline.
     */
    public static byte[] signingInput(long timestampMillis, String nonceHex, String method, String path, byte[] body) {
        if (method.indexOf('\n') >= 0 || path.indexOf('\n') >= 0) {
            throw new IllegalArgumentException("Newline in method or path");
        }
        return ("at.yawk.password/v1/request\n" +
                timestampMillis + "\n" +
                nonceHex + "\n" +
                method + "\n" +
                path + "\n" +
                PlatformDependent.printHexBinary(sha256(body)) + "\n").getBytes(StandardCharsets.UTF_8);
    }

    @SneakyThrows(NoSuchAlgorithmException.class)
    private static byte[] sha256(byte[] data) {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    /**
     * Parse lowercase or uppercase hex, returning {@code null} if it is malformed. (Android lacks
     * {@code java.util.HexFormat}.)
     */
    @Nullable
    public static byte[] parseHex(String hex) {
        if (hex.length() % 2 != 0) {
            return null;
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = hexDigit(hex.charAt(2 * i));
            int lo = hexDigit(hex.charAt(2 * i + 1));
            if (hi < 0 || lo < 0) {
                return null;
            }
            out[i] = (byte) (hi << 4 | lo);
        }
        return out;
    }

    private static int hexDigit(char c) {
        // Character.digit would also accept non-ASCII digits
        return c < 128 ? Character.digit(c, 16) : -1;
    }
}
