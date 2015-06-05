package at.yawk.password;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
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
        Files.write(f, data);
        Path link = directory.resolve("latest");
        if (Files.exists(link)) {
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
