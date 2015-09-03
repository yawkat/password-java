package at.yawk.password;

import java.io.*;
import javax.annotation.Nullable;
import lombok.RequiredArgsConstructor;

/**
 * @author yawkat
 */
@RequiredArgsConstructor
public class FileLocalStorageProvider implements LocalStorageProvider {
    private final File path;

    @Override
    public void save(byte[] data) throws IOException {
        try (FileOutputStream stream = new FileOutputStream(path)) {
            stream.write(data);
        }
    }

    @Nullable
    @Override
    public byte[] load() throws IOException {
        try {
            return getBytes(path);
        } catch (FileNotFoundException notFound) {
            // only safe way to confirm existence
            return null;
        }
    }

    @SuppressWarnings("DuplicateThrows")
    static byte[] getBytes(File path) throws FileNotFoundException, IOException {
        try (FileInputStream stream = new FileInputStream(path);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            copy(stream, out);
            return out.toByteArray();
        }
    }

    static void copy(InputStream stream, OutputStream out) throws IOException {
        byte[] buf = new byte[4096];
        int len;
        while ((len = stream.read(buf)) >= 0) {
            out.write(buf, 0, len);
        }
    }
}
