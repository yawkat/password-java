package at.yawk.password;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import lombok.Getter;

/**
 * So why is this in this project? Fun!
 *
 * @author yawkat
 */
public class HexCharset extends Charset {
    @Getter private static final HexCharset instance = new HexCharset();

    private static final char[] CHARS = "0123456789abcdef".toCharArray();

    private HexCharset() {
        super("Hex", new String[0]);
    }

    @Override
    public boolean contains(Charset cs) {
        return false;
    }

    @Override
    public CharsetDecoder newDecoder() {
        return new CharsetDecoder(this, 2, 2) {
            @Override
            protected CoderResult decodeLoop(ByteBuffer in, CharBuffer out) {
                if (out.remaining() < in.remaining() * 2) {
                    return CoderResult.OVERFLOW;
                }
                while (in.hasRemaining()) {
                    byte b = in.get();
                    out.append(CHARS[(b >>> 4) & 0xf]);
                    out.append(CHARS[b & 0xf]);
                }
                return CoderResult.UNDERFLOW;
            }
        };
    }

    @Override
    public CharsetEncoder newEncoder() {
        return new CharsetEncoder(this, 0.5F, 0.5F) {
            @Override
            protected CoderResult encodeLoop(CharBuffer in, ByteBuffer out) {
                if (out.remaining() < in.remaining() / 2) {
                    return CoderResult.OVERFLOW;
                }
                int n = in.remaining();
                while (in.hasRemaining()) {
                    char c1 = in.get();
                    char c2 = in.get();
                    byte b;
                    if (c1 >= '0' && c1 <= '9') {
                        b = (byte) ((c1 - '0') << 4);
                    } else {
                        int ai = alphabetIndex(c1);
                        if (ai < 6) {
                            b = (byte) (ai << 4);
                        } else {
                            return CoderResult.malformedForLength(n - in.remaining());
                        }
                    }
                    if (c2 >= '0' && c2 <= '9') {
                        b |= (byte) ((c2 - '0') & 0xf);
                    } else {
                        int ai = alphabetIndex(c2);
                        if (ai < 6) {
                            b |= (byte) (ai & 0xf);
                        } else {
                            return CoderResult.malformedForLength(n - in.remaining());
                        }
                    }
                    out.put(b);
                }
                return CoderResult.UNDERFLOW;
            }
        };
    }

    /**
     * Taken from guava, this returns 0 for a/A, 25 for z/Z and a larger value for any non-letter.
     */
    private static int alphabetIndex(char c) {
        return (char) ((c | 0x20) - 'a');
    }
}
