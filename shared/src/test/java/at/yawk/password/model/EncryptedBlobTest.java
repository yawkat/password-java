package at.yawk.password.model;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.util.concurrent.ThreadLocalRandom;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class EncryptedBlobTest {
    static byte[] randomBytes(int len) {
        byte[] bytes = new byte[len];
        ThreadLocalRandom.current().nextBytes(bytes);
        return bytes;
    }

    @Test
    public void testCodec() {
        EncryptedBlob blob = new EncryptedBlob();
        blob.setExpN(20);
        blob.setR(8);
        blob.setP(1);
        blob.setDkLen(32);
        blob.setSalt(randomBytes(32));
        blob.setIv(randomBytes(32));
        blob.setBody(randomBytes(1000));

        ByteBuf buf = Unpooled.buffer();
        blob.write(buf);

        EncryptedBlob copy = new EncryptedBlob();
        copy.read(buf);

        Assert.assertFalse(buf.isReadable());
        Assert.assertEquals(blob, copy);
    }
}