package at.yawk.password.passkey;

import java.io.ByteArrayOutputStream;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.jetbrains.annotations.Nullable;

/**
 * The subset of CBOR (RFC 8949) that WebAuthn and CTAP2 use: integers, byte and text strings, arrays, maps, booleans
 * and null, all of definite length.
 *
 * <p>Values are plain Java objects: {@link Long} (any integer type is accepted when encoding), {@code byte[]},
 * {@link String}, {@link List}, {@link Map}, {@link Boolean} and {@code null}. Maps are encoded in the canonical order
 * of CTAP2 (keys sorted by their encoding, shorter first), so the same value always has the same encoding.
 *
 * @author yawkat
 */
public final class Cbor {
    private static final int MAX_DEPTH = 16;

    private Cbor() {
    }

    public static byte[] encode(@Nullable Object value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        write(out, value);
        return out.toByteArray();
    }

    /**
     * Decode one value that takes up all of {@code data}.
     *
     * @throws CborException if the data is not valid CBOR of the supported subset, or has trailing bytes
     */
    @Nullable
    public static Object decode(byte[] data) throws CborException {
        Reader reader = new Reader(data);
        Object value = reader.read(0);
        if (reader.pos != data.length) {
            throw new CborException("Trailing bytes");
        }
        return value;
    }

    private static void write(ByteArrayOutputStream out, @Nullable Object value) {
        if (value == null) {
            out.write(0xf6);
        } else if (value instanceof Boolean) {
            out.write((Boolean) value ? 0xf5 : 0xf4);
        } else if (value instanceof Long || value instanceof Integer || value instanceof Short || value instanceof Byte) {
            long l = ((Number) value).longValue();
            if (l >= 0) {
                writeHead(out, 0, l);
            } else {
                writeHead(out, 1, -1 - l);
            }
        } else if (value instanceof byte[]) {
            byte[] bytes = (byte[]) value;
            writeHead(out, 2, bytes.length);
            out.write(bytes, 0, bytes.length);
        } else if (value instanceof String) {
            byte[] bytes = ((String) value).getBytes(StandardCharsets.UTF_8);
            writeHead(out, 3, bytes.length);
            out.write(bytes, 0, bytes.length);
        } else if (value instanceof List) {
            List<?> list = (List<?>) value;
            writeHead(out, 4, list.size());
            for (Object element : list) {
                write(out, element);
            }
        } else if (value instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) value;
            TreeMap<byte[], byte[]> sorted = new TreeMap<>(Cbor::compareCanonical);
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (sorted.put(encode(entry.getKey()), encode(entry.getValue())) != null) {
                    throw new IllegalArgumentException("Duplicate map key " + entry.getKey());
                }
            }
            writeHead(out, 5, sorted.size());
            for (Map.Entry<byte[], byte[]> entry : sorted.entrySet()) {
                out.write(entry.getKey(), 0, entry.getKey().length);
                out.write(entry.getValue(), 0, entry.getValue().length);
            }
        } else {
            throw new IllegalArgumentException("Unsupported type " + value.getClass().getName());
        }
    }

    /**
     * The canonical CBOR order of CTAP2: shorter encodings first, then bytewise.
     */
    private static int compareCanonical(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return Integer.compare(a.length, b.length);
        }
        return Arrays.compareUnsigned(a, b);
    }

    private static void writeHead(ByteArrayOutputStream out, int majorType, long argument) {
        int major = majorType << 5;
        if (argument < 0) {
            // unsigned values above Long.MAX_VALUE: only -1 - Long.MIN_VALUE, which can't be passed in
            throw new IllegalArgumentException();
        } else if (argument < 24) {
            out.write(major | (int) argument);
        } else if (argument <= 0xff) {
            out.write(major | 24);
            out.write((int) argument);
        } else if (argument <= 0xffff) {
            out.write(major | 25);
            writeBigEndian(out, argument, 2);
        } else if (argument <= 0xffffffffL) {
            out.write(major | 26);
            writeBigEndian(out, argument, 4);
        } else {
            out.write(major | 27);
            writeBigEndian(out, argument, 8);
        }
    }

    private static void writeBigEndian(ByteArrayOutputStream out, long value, int bytes) {
        for (int i = bytes - 1; i >= 0; i--) {
            out.write((int) (value >>> (i * 8)));
        }
    }

    private static final class Reader {
        private final byte[] data;
        private int pos;

        Reader(byte[] data) {
            this.data = data;
        }

        private int readByte() throws CborException {
            if (pos >= data.length) {
                throw new CborException("Unexpected end of data");
            }
            return data[pos++] & 0xff;
        }

        private long readArgument(int info) throws CborException {
            if (info < 24) {
                return info;
            }
            int bytes;
            switch (info) {
                case 24:
                    bytes = 1;
                    break;
                case 25:
                    bytes = 2;
                    break;
                case 26:
                    bytes = 4;
                    break;
                case 27:
                    bytes = 8;
                    break;
                default:
                    throw new CborException("Unsupported additional information " + info);
            }
            long value = 0;
            for (int i = 0; i < bytes; i++) {
                value = (value << 8) | readByte();
            }
            return value;
        }

        /**
         * A length that fits into the remaining data. Every element takes at least one byte, so this also bounds the
         * size of arrays and maps.
         */
        private int readLength(int info) throws CborException {
            long length = readArgument(info);
            if (length < 0 || length > data.length - pos) {
                throw new CborException("Length out of bounds");
            }
            return (int) length;
        }

        @Nullable
        Object read(int depth) throws CborException {
            if (depth > MAX_DEPTH) {
                throw new CborException("Nested too deeply");
            }
            int initial = readByte();
            int major = initial >>> 5;
            int info = initial & 0x1f;
            switch (major) {
                case 0: {
                    long value = readArgument(info);
                    if (value < 0) {
                        throw new CborException("Integer out of range");
                    }
                    return value;
                }
                case 1: {
                    long value = readArgument(info);
                    if (value < 0) {
                        throw new CborException("Integer out of range");
                    }
                    return -1 - value;
                }
                case 2: {
                    int length = readLength(info);
                    byte[] bytes = Arrays.copyOfRange(data, pos, pos + length);
                    pos += length;
                    return bytes;
                }
                case 3: {
                    int length = readLength(info);
                    String text;
                    try {
                        text = StandardCharsets.UTF_8.newDecoder()
                                .onMalformedInput(CodingErrorAction.REPORT)
                                .onUnmappableCharacter(CodingErrorAction.REPORT)
                                .decode(java.nio.ByteBuffer.wrap(data, pos, length))
                                .toString();
                    } catch (CharacterCodingException e) {
                        throw new CborException("Invalid UTF-8");
                    }
                    pos += length;
                    return text;
                }
                case 4: {
                    int length = readLength(info);
                    List<Object> list = new ArrayList<>(length);
                    for (int i = 0; i < length; i++) {
                        list.add(read(depth + 1));
                    }
                    return list;
                }
                case 5: {
                    int length = readLength(info);
                    Map<Object, Object> map = new LinkedHashMap<>();
                    for (int i = 0; i < length; i++) {
                        Object key = read(depth + 1);
                        if (key instanceof byte[] || key instanceof List || key instanceof Map) {
                            // no equals() that a map could use
                            throw new CborException("Unsupported map key type");
                        }
                        if (map.containsKey(key)) {
                            throw new CborException("Duplicate map key");
                        }
                        map.put(key, read(depth + 1));
                    }
                    return map;
                }
                case 6:
                    // a tag: ignore it, the content is what counts
                    readArgument(info);
                    return read(depth + 1);
                default:
                    switch (info) {
                        case 20:
                            return false;
                        case 21:
                            return true;
                        case 22:
                        case 23:
                            return null;
                        default:
                            throw new CborException("Unsupported simple value or float " + info);
                    }
            }
        }
    }
}
