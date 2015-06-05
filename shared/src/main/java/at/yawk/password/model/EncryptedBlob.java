package at.yawk.password.model;

import at.yawk.password.Encoding;
import io.netty.buffer.ByteBuf;
import java.nio.ByteOrder;
import lombok.Data;

/**
 * @author yawkat
 */
@Data
public class EncryptedBlob {
    private int expN;
    private int r;
    private int p;
    private int dkLen;
    private byte[] salt;
    private byte[] iv;
    private byte[] body;

    public void write(ByteBuf buf) {
        buf.order(ByteOrder.BIG_ENDIAN);
        buf.writeInt(expN);
        buf.writeInt(r);
        buf.writeInt(p);
        buf.writeInt(dkLen);
        buf.writeInt(salt.length);
        buf.writeBytes(salt);
        assert iv.length == dkLen;
        buf.writeBytes(iv); // length always dkLen
        buf.writeInt(body.length);
        buf.writeBytes(body);
    }

    public boolean read(ByteBuf buf) {
        if (buf.readableBytes() < 24) { return false; }
        buf.markReaderIndex();
        buf.order(ByteOrder.BIG_ENDIAN);

        expN = buf.readInt();
        r = buf.readInt();
        p = buf.readInt();
        dkLen = buf.readInt();
        salt = Encoding.readLengthPrefixedByteArray(buf);
        if (salt == null || buf.readableBytes() < dkLen) {
            buf.resetReaderIndex();
            return false;
        }
        iv = new byte[dkLen];
        buf.readBytes(iv);
        body = Encoding.readLengthPrefixedByteArray(buf);
        if (body == null) {
            buf.resetReaderIndex();
            return false;
        }
        return true;
    }
}
