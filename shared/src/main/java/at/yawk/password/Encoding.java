package at.yawk.password;

import io.netty.buffer.ByteBuf;

/**
 * @author yawkat
 */
public class Encoding {
    private Encoding() {}

    public static byte[] toByteArray(ByteBuf buf) {
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        return bytes;
    }

    public static void writeLengthPrefixedByteArray(ByteBuf buf, byte[] array) {
        buf.writeInt(array.length);
        buf.writeBytes(array);
    }

    public static byte[] readLengthPrefixedByteArray(ByteBuf buf) {
        if (buf.readableBytes() < 4) {
            return null;
        }
        int len = buf.readInt();
        assert len >= 0 : len;
        if (buf.readableBytes() < len) {
            return null;
        }
        byte[] bytes = new byte[len];
        buf.readBytes(bytes);
        return bytes;
    }
}
