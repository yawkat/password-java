package at.yawk.password.client;

import at.yawk.password.HashUtil;
import at.yawk.password.PlatformDependent;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.EncryptedBlob;
import at.yawk.password.model.ScryptParameters;
import com.fasterxml.jackson.databind.ObjectMapper;
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
        Cipher decryptCipher = Cipher.getInstance("AES/CFB/NoPadding");
        decryptCipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new IvParameterSpec(msg.getIv())
        );
        byte[] dec = decryptCipher.doFinal(msg.getBody());

        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(key, "HmacSHA512"));
        // use content
        mac.update(dec, HMAC_LENGTH, dec.length - HMAC_LENGTH);
        byte[] expectedMac = mac.doFinal();

        for (int i = 0; i < HMAC_LENGTH; i++) {
            if (dec[i] != expectedMac[i]) {
                throw new Exception(
                        "Invalid HMAC: expected " +
                        PlatformDependent.printHexBinary(expectedMac) +
                        " but was " +
                        PlatformDependent.printHexBinary(Arrays.copyOf(dec, HMAC_LENGTH))
                );
            }
        }

        return objectMapper.reader()
                .forType(DecryptedBlob.class)
                .readValue(dec, HMAC_LENGTH, dec.length - HMAC_LENGTH);
    }
}
