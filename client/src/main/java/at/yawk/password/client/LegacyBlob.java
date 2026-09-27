package at.yawk.password.client;

import at.yawk.password.model.DecryptedBlob;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.experimental.UtilityClass;
import org.bouncycastle.crypto.generators.SCrypt;

/**
 * Reader for the database format before {@link BlobCodec}, for the one-time migration of a local copy: a header of
 * scrypt parameters and salt, then AES/CFB of {@code HMAC-SHA512 ‖ json}, all with the same scrypt key.
 *
 * <p>Only the parameters every old client wrote are accepted (scrypt N=2^16, r=8, p=1, 32 byte key, 32 byte salt),
 * so a crafted blob can't make the client do more work. Remove once all copies are migrated.
 *
 * @author yawkat
 */
@UtilityClass
class LegacyBlob {
    private static final int EXP_N = 16;
    private static final int R = 8;
    private static final int P = 1;
    private static final int KEY_LENGTH = 32;
    private static final int SALT_LENGTH = 32;
    private static final int IV_LENGTH = 16;
    private static final int HMAC_LENGTH = 64;
    private static final int BODY_OFFSET = 4 * 4 + 4 + SALT_LENGTH + IV_LENGTH + 4;

    /**
     * @return Whether the data starts like a legacy blob (the fixed scrypt parameters).
     */
    static boolean isLegacy(byte[] blob) {
        if (blob.length < BODY_OFFSET) {
            return false;
        }
        ByteBuffer buf = ByteBuffer.wrap(blob);
        return buf.getInt() == EXP_N && buf.getInt() == R && buf.getInt() == P && buf.getInt() == KEY_LENGTH &&
               buf.getInt() == SALT_LENGTH;
    }

    static DecryptedBlob decrypt(ObjectMapper objectMapper, byte[] password, byte[] blob) throws Exception {
        if (!isLegacy(blob)) {
            throw new Exception("Invalid database: not a legacy database");
        }
        ByteBuffer buf = ByteBuffer.wrap(blob);
        buf.position(4 * 5);
        byte[] salt = new byte[SALT_LENGTH];
        buf.get(salt);
        byte[] iv = new byte[IV_LENGTH];
        buf.get(iv);
        int bodyLength = buf.getInt();
        if (bodyLength < HMAC_LENGTH || bodyLength != buf.remaining()) {
            throw new Exception("Invalid database: bad length");
        }

        byte[] key = SCrypt.generate(password, salt, 1 << EXP_N, R, P, KEY_LENGTH);
        byte[] dec = null;
        byte[] actualMac = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            dec = cipher.doFinal(blob, BODY_OFFSET, bodyLength);

            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(new SecretKeySpec(key, "HmacSHA512"));
            mac.update(dec, HMAC_LENGTH, dec.length - HMAC_LENGTH);
            byte[] expectedMac = mac.doFinal();
            // do not include any decrypted bytes in the message, they may contain plaintext
            actualMac = Arrays.copyOf(dec, HMAC_LENGTH);
            if (!MessageDigest.isEqual(actualMac, expectedMac)) {
                throw new WrongPasswordException();
            }
            return objectMapper.readerFor(DecryptedBlob.class).readValue(dec, HMAC_LENGTH, dec.length - HMAC_LENGTH);
        } finally {
            Arrays.fill(key, (byte) 0);
            if (dec != null) {
                Arrays.fill(dec, (byte) 0);
            }
            if (actualMac != null) {
                Arrays.fill(actualMac, (byte) 0);
            }
        }
    }
}
