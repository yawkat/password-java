package at.yawk.password;

import java.io.*;
import javax.annotation.Nullable;
import lombok.RequiredArgsConstructor;

/**
 * Storage provider that keeps all old copies of the database in backup.
 *
 * @author yawkat
 */
@RequiredArgsConstructor
public class MultiFileLocalStorageProvider implements LocalStorageProvider {
    private final File directory;

    @Override
    public void save(byte[] data) throws IOException {
        File f = new File(directory, PlatformDependent.nowTimestamp());

        try (OutputStream out = new FileOutputStream(f)) {
            PlatformDependent.setOwnerOnlyPermissions(f);
            out.write(data);
        }

        File link = new File(directory, "latest");
        //noinspection ResultOfMethodCallIgnored
        link.delete();

        PlatformDependent.symlinkOrCopy(f, link);
    }

    @Nullable
    @Override
    public byte[] load() throws IOException {
        try {
            return FileLocalStorageProvider.getBytes(new File(directory, "latest"));
        } catch (FileNotFoundException notFound) {
            // only safe way to confirm existence
            return null;
        }
    }
}
