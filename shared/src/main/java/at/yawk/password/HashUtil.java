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
    @SneakyThrows(NoSuchAlgorithmException.class)
    public static byte[] generateRandomBytes(int length)  {
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[length];
        rng.nextBytes(salt);
        return salt;
    }

    @SneakyThrows(NoSuchAlgorithmException.class)
    public static byte[] sha256(byte[]... parts) {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        for (byte[] part : parts) {
            digest.update(part);
        }
        return digest.digest();
    }
}
