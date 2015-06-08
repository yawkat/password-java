package at.yawk.password.model;

import at.yawk.password.Encoding;
import io.netty.buffer.ByteBuf;
import java.nio.ByteOrder;
import lombok.Data;

/**
 * @author yawkat
 */
@Data
public class SignedBlob {
    private byte[] key;
    private byte[] signature;
    private byte[] body;

    public boolean read(ByteBuf buf) {
        buf.order(ByteOrder.BIG_ENDIAN);
        buf.markReaderIndex();
        buf.resetReaderIndex();
        key = Encoding.readLengthPrefixedByteArray(buf);
        if (key == null) {
            buf.resetReaderIndex();
            return false;
        }
        signature = Encoding.readLengthPrefixedByteArray(buf);
        if (signature == null) {
            buf.resetReaderIndex();
            return false;
        }
        body = Encoding.readLengthPrefixedByteArray(buf);
        if (body == null) {
            buf.resetReaderIndex();
            return false;
        }
        return true;
    }

    public void write(ByteBuf buf) {
        buf.order(ByteOrder.BIG_ENDIAN);
        Encoding.writeLengthPrefixedByteArray(buf, key);
        Encoding.writeLengthPrefixedByteArray(buf, signature);
        Encoding.writeLengthPrefixedByteArray(buf, body);
        buf.markReaderIndex();
        buf.resetReaderIndex();
    }
}
