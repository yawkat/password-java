package at.yawk.password.client;

import at.yawk.password.HashUtil;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.EncryptedBlob;
import at.yawk.password.model.ScryptParameters;
import tools.jackson.databind.ObjectMapper;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.experimental.UtilityClass;

/**
 * @author yawkat
 */
@UtilityClass
class AesCodec {
    private static final int HMAC_LENGTH = 64;

    /**
     * Default parameters for container encryption. Salt is generated.
     */
    private static final ScryptParameters DEFAULT_CONTAINER_PARAMS = new ScryptParameters(16, 8, 1, 32, null);

    public static EncryptedBlob encrypt(ObjectMapper objectMapper, byte[] password, DecryptedBlob msg)
            throws Exception {
        ScryptParameters params = DEFAULT_CONTAINER_PARAMS.withSalt(HashUtil.generateRandomBytes(32));

        byte[] key = params.runScrypt(password);
        byte[] body = objectMapper.writeValueAsBytes(msg);
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(key, "HmacSHA512"));
        byte[] hmac = mac.doFinal(body);

        Cipher encryptCipher = Cipher.getInstance("AES/CFB/NoPadding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        byte[] encryptedBody = new byte[hmac.length + body.length];
        encryptCipher.update(hmac, 0, hmac.length, encryptedBody, 0);
        encryptCipher.doFinal(body, 0, body.length, encryptedBody, hmac.length);

        EncryptedBlob encryptedBlob = new EncryptedBlob();
        encryptedBlob.setParameters(params);
        encryptedBlob.setIv(encryptCipher.getIV());
        encryptedBlob.setBody(encryptedBody);
        return encryptedBlob;
    }

    public static DecryptedBlob decrypt(ObjectMapper objectMapper, byte[] password, EncryptedBlob msg)
            throws Exception {
        byte[] key = msg.getParameters().runScrypt(password);
        byte[] dec = null;
        byte[] actualMac = null;
        try {
            Cipher decryptCipher = Cipher.getInstance("AES/CFB/NoPadding");
            decryptCipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(msg.getIv())
            );
            dec = decryptCipher.doFinal(msg.getBody());
            if (dec.length < HMAC_LENGTH) {
                throw new Exception("Invalid ciphertext: too short");
            }

            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(new SecretKeySpec(key, "HmacSHA512"));
            // use content
            mac.update(dec, HMAC_LENGTH, dec.length - HMAC_LENGTH);
            byte[] expectedMac = mac.doFinal();

            // do not include any decrypted bytes in the message, they may contain plaintext
            actualMac = Arrays.copyOf(dec, HMAC_LENGTH);
            if (!MessageDigest.isEqual(actualMac, expectedMac)) {
                throw new Exception("Invalid HMAC");
            }

            return objectMapper.reader()
                    .forType(DecryptedBlob.class)
                    .readValue(dec, HMAC_LENGTH, dec.length - HMAC_LENGTH);
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
