package at.yawk.password;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;

/**
 * @author yawkat
 */
@UtilityClass
public class HashUtil {
    public static byte[] generateRandomBytes(int length)  {
        SecureRandom rng = new SecureRandom();
        byte[] salt = new byte[length];
        rng.nextBytes(salt);
        return salt;
    }

    /**
     * SHA-512 over the concatenation of {@code parts}.
     */
    @SneakyThrows(NoSuchAlgorithmException.class)
    public static byte[] sha512(byte[]... parts) {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        for (byte[] part : parts) {
            digest.update(part);
        }
        return digest.digest();
    }
}
