package at.yawk.password.model;

import at.yawk.password.ClientServerTest;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class EncryptedBlobTest {
    @Test
    public void testCodec() {
        EncryptedBlob blob = new EncryptedBlob();
        blob.setExpN(20);
        blob.setR(8);
        blob.setP(1);
        blob.setDkLen(32);
        blob.setSalt(ClientServerTest.randomBytes(32));
        blob.setIv(ClientServerTest.randomBytes(16));
        blob.setBody(ClientServerTest.randomBytes(1000));

        ByteBuf buf = Unpooled.buffer();
        blob.write(buf);

        EncryptedBlob copy = new EncryptedBlob();
        copy.read(buf);

        Assert.assertFalse(buf.isReadable());
        Assert.assertEquals(blob, copy);
    }
}