package at.yawk.password.model;

import at.yawk.password.HashUtil;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class EncryptedBlobTest {
    @Test
    public void testCodec() {
        EncryptedBlob blob = new EncryptedBlob();
        blob.setParameters(new ScryptParameters(20, 8, 1, 32, HashUtil.generateRandomBytes(32)));
        blob.setIv(HashUtil.generateRandomBytes(16));
        blob.setBody(HashUtil.generateRandomBytes(1000));

        byte[] bytes = blob.write();

        EncryptedBlob copy = new EncryptedBlob();
        copy.read(bytes);

        Assert.assertEquals(blob, copy);
    }
}