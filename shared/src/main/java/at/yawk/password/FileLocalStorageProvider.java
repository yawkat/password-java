package at.yawk.password;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.annotation.Nullable;
import lombok.RequiredArgsConstructor;

/**
 * @author yawkat
 */
@RequiredArgsConstructor
public class FileLocalStorageProvider implements LocalStorageProvider {
    private final Path path;

    @Override
    public void save(byte[] data) throws IOException {
        Files.write(path, data);
    }

    @Nullable
    @Override
    public byte[] load() throws IOException {
        if (!Files.exists(path)) { return null; }
        return Files.readAllBytes(path);
    }
}
