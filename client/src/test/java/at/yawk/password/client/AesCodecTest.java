package at.yawk.password.client;

import at.yawk.password.HashUtil;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.EncryptedBlob;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.model.PasswordEntry;
import com.fasterxml.jackson.databind.ObjectMapper;
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
}
