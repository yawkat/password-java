package at.yawk.password.client;

import at.yawk.password.ClientServerTest;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.EncryptedBlob;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.model.PasswordEntry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyPairGenerator;
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
        startBlob.setRsa(DecryptedBlob.RsaKeyPair.ofKeyPair(KeyPairGenerator.getInstance("RSA").generateKeyPair()));
        startBlob.setData(new PasswordBlob() {{
            getPasswords().add(new PasswordEntry() {{
                setName("name");
                setValue("password 123456789ß^1u9u0oshsbv");
            }});
        }});

        EncryptedBlob encrypted = Encrypter.encrypt(om, password, startBlob);
        DecryptedBlob decrypted = Decrypter.decrypt(om, password, encrypted);

        Assert.assertEquals(startBlob, decrypted);
    }
}
