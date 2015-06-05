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

    public static byte[] readLengthPrefixedByteArray(ByteBuf buf) {
        if (!buf.isReadable()) {
            return null;
        }
        int len = buf.readInt();
        if (len > buf.readableBytes()) {
            return null;
        }
        byte[] bytes = new byte[len];
        buf.readBytes(bytes);
        return bytes;
    }
}
