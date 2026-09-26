package at.yawk.password.client;

import at.yawk.password.HashUtil;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.EncryptedBlob;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.model.PasswordEntry;
import tools.jackson.databind.ObjectMapper;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class AesCodecTest {
    @Test
    public void testEncryptDecrypt() throws Exception {
        ObjectMapper om = new ObjectMapper();
        byte[] password = HashUtil.generateRandomBytes(100);

        DecryptedBlob startBlob = new DecryptedBlob();
        startBlob.setData(new PasswordBlob() {{
            getPasswords().add(new PasswordEntry() {{
                setName("name");
                setValue("password 1234567891u9u0oshsbv");
            }});
        }});

        EncryptedBlob encrypted = AesCodec.encrypt(om, password, startBlob);
        DecryptedBlob decrypted = AesCodec.decrypt(om, password, encrypted);

        Assert.assertEquals(startBlob, decrypted);
    }

    @Test
    public void testTamperedMessageDoesNotLeakPlaintext() throws Exception {
        ObjectMapper om = new ObjectMapper();
        byte[] password = HashUtil.generateRandomBytes(100);

        DecryptedBlob startBlob = new DecryptedBlob();
        startBlob.setData(new PasswordBlob());

        EncryptedBlob encrypted = AesCodec.encrypt(om, password, startBlob);
        // flip a bit in the HMAC section
        encrypted.getBody()[0] ^= 1;

        try {
            AesCodec.decrypt(om, password, encrypted);
            Assert.fail("Expected HMAC failure");
        } catch (Exception e) {
            Assert.assertEquals(e.getMessage(), "Invalid HMAC");
        }
    }

    @Test
    public void testShortBody() throws Exception {
        ObjectMapper om = new ObjectMapper();
        byte[] password = HashUtil.generateRandomBytes(100);

        EncryptedBlob encrypted = AesCodec.encrypt(om, password, new DecryptedBlob());
        encrypted.setBody(new byte[10]);

        try {
            AesCodec.decrypt(om, password, encrypted);
            Assert.fail("Expected decryption failure");
        } catch (Exception e) {
            // testng: assertEquals(actual, expected)
            Assert.assertEquals(e.getMessage(), "Invalid ciphertext: too short");
        }
    }

    @Test
    public void testWrongPassword() throws Exception {
        ObjectMapper om = new ObjectMapper();
        DecryptedBlob startBlob = new DecryptedBlob();
        startBlob.setData(new PasswordBlob());

        EncryptedBlob encrypted = AesCodec.encrypt(om, HashUtil.generateRandomBytes(100), startBlob);

        try {
            AesCodec.decrypt(om, HashUtil.generateRandomBytes(100), encrypted);
            Assert.fail("Expected HMAC failure");
        } catch (Exception e) {
            Assert.assertEquals(e.getMessage(), "Invalid HMAC");
        }
    }
}
