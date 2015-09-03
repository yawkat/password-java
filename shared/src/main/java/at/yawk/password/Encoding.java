package at.yawk.password;

import java.nio.ByteBuffer;

/**
 * @author yawkat
 */
public class Encoding {
    private Encoding() {}

    public static void writeLengthPrefixedByteArray(ByteBuffer buf, byte[] array) {
        buf.putInt(array.length);
        buf.put(array);
    }

    public static byte[] readLengthPrefixedByteArray(ByteBuffer buf) {
        int len = buf.getInt();
        assert len >= 0 : len;
        byte[] bytes = new byte[len];
        buf.get(bytes);
        return bytes;
    }
}
