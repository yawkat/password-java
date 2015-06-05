package at.yawk.password.client;

import at.yawk.password.ClientServerTest;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.EncryptedBlob;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class EncrypterDecrypterTest {
    @Test
    public void testEncryptDecrypt() throws Exception {
        ObjectMapper om = new ObjectMapper();
        byte[] password = ClientServerTest.randomBytes(100);

        DecryptedBlob startBlob = new DecryptedBlob();

        EncryptedBlob encrypted = Encrypter.encrypt(om, password, startBlob);
        DecryptedBlob decrypted = Decrypter.decrypt(om, password, encrypted);

        Assert.assertEquals(startBlob, decrypted);
    }
}
