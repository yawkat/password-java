package at.yawk.password.model;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class SignedBlobTest {
    @Test
    public void testCodec() {
        SignedBlob blob = new SignedBlob();
        blob.setKey(EncryptedBlobTest.randomBytes(32));
        blob.setSignature(EncryptedBlobTest.randomBytes(64));
        blob.setBody(EncryptedBlobTest.randomBytes(1234));

        ByteBuf buf = Unpooled.buffer();
        blob.write(buf);

        SignedBlob copy = new SignedBlob();
        copy.read(buf);

        Assert.assertFalse(buf.isReadable());
        Assert.assertEquals(blob, copy);
    }
}