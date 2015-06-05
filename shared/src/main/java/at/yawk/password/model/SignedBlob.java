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
public class SignedBlob {
    private static final int SIGNATURE_LENGTH = 128;

    private byte[] key;
    private byte[] signature;
    private byte[] body;

    public boolean read(ByteBuf buf) {
        System.out.println("Read S " + buf.toString(HexCharset.getInstance()));
        buf.order(ByteOrder.BIG_ENDIAN);
        buf.markReaderIndex();
        key = Encoding.readLengthPrefixedByteArray(buf);
        if (buf.readableBytes() < SIGNATURE_LENGTH + 1) {
            buf.resetReaderIndex();
            return false;
        }
        signature = new byte[SIGNATURE_LENGTH];
        buf.readBytes(signature);
        body = Encoding.readLengthPrefixedByteArray(buf);
        if (key == null || body == null) {
            buf.resetReaderIndex();
            return false;
        }
        return true;
    }

    public void write(ByteBuf buf) {
        buf.order(ByteOrder.BIG_ENDIAN);
        buf.writeInt(key.length);
        buf.writeBytes(key);
        assert signature.length == SIGNATURE_LENGTH : signature.length;
        buf.writeBytes(signature);
        buf.writeInt(body.length);
        buf.writeBytes(body);
        System.out.println("Write S " + buf.toString(HexCharset.getInstance()));
    }
}
