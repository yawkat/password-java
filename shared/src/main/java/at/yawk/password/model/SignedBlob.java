package at.yawk.password.model;

import at.yawk.password.Encoding;
import io.netty.buffer.ByteBuf;
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
        buf.markReaderIndex();
        key = Encoding.readLengthPrefixedByteArray(buf);
        if (buf.readableBytes() < 64) {
            buf.resetReaderIndex();
            return false;
        }
        signature = new byte[64];
        buf.readBytes(signature);
        body = Encoding.readLengthPrefixedByteArray(buf);
        if (key == null || body == null) {
            buf.resetReaderIndex();
            return false;
        }
        return true;
    }

    public void write(ByteBuf buf) {
        buf.writeInt(key.length);
        buf.writeBytes(key);
        buf.writeBytes(signature);
        buf.writeInt(body.length);
        buf.writeBytes(body);
    }
}
