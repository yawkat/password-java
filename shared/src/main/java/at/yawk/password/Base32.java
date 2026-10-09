package at.yawk.password;

import java.util.Arrays;
import lombok.experimental.UtilityClass;

/**
 * Base32 of RFC 4648 (alphabet {@code A-Z2-7}), the encoding of TOTP secrets.
 *
 * <p>Decoding is lenient in the ways that secrets are written down: lowercase, spaces and dashes between groups, and
 * missing or present {@code =} padding are accepted. So are unused bits of the last character that are not zero, as
 * other implementations (Python, Google Authenticator) do: they don't affect the decoded bytes, and generators that
 * pick random Base32 characters produce them. {@link #canonical} gives the one spelling of a value.
 *
 * @author yawkat
 */
@UtilityClass
public class Base32 {
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /**
     * @return The encoding without padding
     */
    public static String encode(byte[] data) {
        StringBuilder out = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = buffer << 8 | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                out.append(ALPHABET.charAt(buffer >>> bits & 31));
            }
        }
        if (bits > 0) {
            out.append(ALPHABET.charAt(buffer << (5 - bits) & 31));
        }
        return out.toString();
    }

    /**
     * @throws IllegalArgumentException if the text is not Base32
     */
    public static byte[] decode(String text) {
        String normalized = normalize(text);
        // 8 characters encode 5 bytes. 1, 3 or 6 characters left over can't be the end of any byte sequence.
        int rest = normalized.length() % 8;
        if (rest == 1 || rest == 3 || rest == 6) {
            throw new IllegalArgumentException("Invalid Base32 length");
        }
        byte[] out = new byte[normalized.length() * 5 / 8];
        int buffer = 0;
        int bits = 0;
        int index = 0;
        for (int i = 0; i < normalized.length(); i++) {
            buffer = buffer << 5 | ALPHABET.indexOf(normalized.charAt(i));
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out[index++] = (byte) (buffer >>> bits);
            }
        }
        return out;
    }

    /**
     * @return The encoding that {@link #encode} gives for the decoded text: upper case, no separators or padding, and
     * zero unused bits
     * @throws IllegalArgumentException if the text is not Base32
     */
    public static String canonical(String text) {
        byte[] bytes = decode(text);
        try {
            return encode(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * @return The text in upper case, without separators and padding
     * @throws IllegalArgumentException if the text contains other characters than Base32, separators and trailing
     * padding
     */
    static String normalize(String text) {
        StringBuilder out = new StringBuilder(text.length());
        boolean padding = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == ' ' || c == '-') {
                continue;
            }
            if (c == '=') {
                padding = true;
                continue;
            }
            char upper = c >= 'a' && c <= 'z' ? (char) (c - 'a' + 'A') : c;
            if (padding || ALPHABET.indexOf(upper) < 0) {
                throw new IllegalArgumentException("Invalid Base32 character at position " + i);
            }
            out.append(upper);
        }
        return out.toString();
    }
}
