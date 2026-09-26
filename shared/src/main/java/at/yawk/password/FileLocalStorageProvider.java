package at.yawk.password;

import java.io.*;
import org.jetbrains.annotations.Nullable;
import lombok.RequiredArgsConstructor;

/**
 * @author yawkat
 */
@RequiredArgsConstructor
public class FileLocalStorageProvider implements LocalStorageProvider {
    private final File path;

    @Override
    public void save(byte[] data) throws IOException {
        PlatformDependent.writeOwnerOnlyAtomically(path, data);
    }

    /**
     * Restrict the permissions of the storage file to the owner, if it exists. Useful on startup to fix files that
     * were created with looser permissions.
     */
    public void restrictPermissions() throws IOException {
        if (path.exists()) {
            PlatformDependent.setOwnerOnlyPermissions(path);
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
