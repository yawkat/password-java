package at.yawk.password;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import javax.annotation.Nullable;
import lombok.RequiredArgsConstructor;

/**
 * Storage provider that keeps all old copies of the database in backup.
 *
 * @author yawkat
 */
@RequiredArgsConstructor
public class MultiFileLocalStorageProvider implements LocalStorageProvider {
    private final Path directory;

    @Override
    public void save(byte[] data) throws IOException {
        Path f = directory.resolve(Instant.now().toString());

        try (OutputStream out = Files.newOutputStream(f)) {
            Files.setPosixFilePermissions(f, new HashSet<>(Arrays.asList(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            )));
            out.write(data);
        }

        Path link = directory.resolve("latest");
        if (Files.exists(link, LinkOption.NOFOLLOW_LINKS)) {
            Files.delete(link);
        }
        Files.createSymbolicLink(link, f);
    }

    @Nullable
    @Override
    public byte[] load() throws IOException {
        Path latest = directory.resolve("latest");
        if (!Files.exists(latest)) { return null; }
        return Files.readAllBytes(latest);
    }
}
