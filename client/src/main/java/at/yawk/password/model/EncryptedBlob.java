package at.yawk.password.model;

import at.yawk.password.Encoding;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import lombok.Data;

/**
 * @author yawkat
 */
@Data
public class EncryptedBlob {
    private static final int IV_LENGTH = 16;

    private ScryptParameters parameters;
    private byte[] iv;
    private byte[] body;

    public byte[] write() {
        int expectedBytes = 16 + 4 + parameters.getSalt().length +
                            IV_LENGTH +
                            4 + body.length;
        ByteBuffer buf = ByteBuffer.allocate(expectedBytes);

        buf.order(ByteOrder.BIG_ENDIAN);
        buf.putInt(parameters.getExpN());
        buf.putInt(parameters.getR());
        buf.putInt(parameters.getP());
        buf.putInt(parameters.getDkLen());
        Encoding.writeLengthPrefixedByteArray(buf, parameters.getSalt());
        assert iv.length == IV_LENGTH : iv.length;
        buf.put(iv); // length always 16
        Encoding.writeLengthPrefixedByteArray(buf, body);
        return buf.array();
    }

    public void read(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);

        int expN = buf.getInt();
        int r = buf.getInt();
        int p = buf.getInt();
        int dkLen = buf.getInt();
        byte[] salt = Encoding.readLengthPrefixedByteArray(buf);
        parameters = new ScryptParameters(expN, r, p, dkLen, salt);

        iv = new byte[IV_LENGTH];
        buf.get(iv);
        body = Encoding.readLengthPrefixedByteArray(buf);
    }
}
