package at.yawk.password.model;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.util.concurrent.ThreadLocalRandom;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class SignedBlobTest {
    static byte[] randomBytes(int len) {
        byte[] bytes = new byte[len];
        ThreadLocalRandom.current().nextBytes(bytes);
        return bytes;
    }

    @Test
    public void testCodec() {
        SignedBlob blob = new SignedBlob();
        blob.setKey(randomBytes(32));
        blob.setSignature(randomBytes(64));
        blob.setBody(randomBytes(1234));

        ByteBuf buf = Unpooled.buffer();
        blob.write(buf);

        SignedBlob copy = new SignedBlob();
        copy.read(buf);

        Assert.assertFalse(buf.isReadable());
        Assert.assertEquals(blob, copy);
    }
}