package at.yawk.password.model;

import at.yawk.password.Encoding;
import at.yawk.password.HexCharset;
import io.netty.buffer.ByteBuf;
import java.nio.ByteOrder;
import lombok.Data;

/**
 * @author yawkat
 */
@Data
public class EncryptedBlob {
    private static final int IV_LENGTH = 16;

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
        Encoding.writeLengthPrefixedByteArray(buf, salt);
        assert iv.length == IV_LENGTH : iv.length;
        buf.writeBytes(iv); // length always 16
        Encoding.writeLengthPrefixedByteArray(buf, body);
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
        if (salt == null || buf.readableBytes() < IV_LENGTH + 4) {
            buf.resetReaderIndex();
            return false;
        }
        iv = new byte[IV_LENGTH];
        buf.readBytes(iv);
        body = Encoding.readLengthPrefixedByteArray(buf);
        if (body == null) {
            buf.resetReaderIndex();
            return false;
        }
        return true;
    }
}
