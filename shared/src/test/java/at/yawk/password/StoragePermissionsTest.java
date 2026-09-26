package at.yawk.password;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;
import org.testng.SkipException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

public class StoragePermissionsTest {
    private Path dir;

    @BeforeMethod
    public void setUp() throws IOException {
        dir = Files.createTempDirectory("storage-permissions-test");
        if (!PlatformDependent.isPosix(dir)) {
            throw new SkipException("POSIX permissions not supported");
        }
    }

    @AfterMethod(alwaysRun = true)
    public void tearDown() throws IOException {
        try (Stream<Path> files = Files.walk(dir)) {
            for (Path p : files.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(p);
            }
        }
    }

    private static String perms(Path path) throws IOException {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(path));
    }

    private List<Path> listDir() throws IOException {
        try (Stream<Path> files = Files.list(dir)) {
            return files.toList();
        }
    }

    private Path worldReadableFile(String name) throws IOException {
        Path file = dir.resolve(name);
        Files.write(file, new byte[]{ 9 });
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"));
        return file;
    }

    @Test
    public void fileProviderCreatesOwnerOnly() throws IOException {
        Path file = dir.resolve("shared-secret");
        FileLocalStorageProvider provider = new FileLocalStorageProvider(file.toFile());
        provider.save(new byte[]{ 1, 2, 3 });

        assertEquals(perms(file), "rw-------");
        assertEquals(provider.load(), new byte[]{ 1, 2, 3 });
        assertEquals(listDir(), List.of(file), "temp file should not be left behind");
    }

    @Test
    public void fileProviderSaveReplacesWorldReadableFile() throws IOException {
        Path file = worldReadableFile("shared-secret");

        FileLocalStorageProvider provider = new FileLocalStorageProvider(file.toFile());
        provider.save(new byte[]{ 1, 2, 3 });

        assertEquals(perms(file), "rw-------");
        assertEquals(provider.load(), new byte[]{ 1, 2, 3 });
    }

    @Test
    public void fileProviderRestrictPermissionsTightensExistingFile() throws IOException {
        Path file = worldReadableFile("shared-secret");

        FileLocalStorageProvider provider = new FileLocalStorageProvider(file.toFile());
        provider.restrictPermissions();

        assertEquals(perms(file), "rw-------");
        assertEquals(provider.load(), new byte[]{ 9 });
    }

    @Test
    public void fileProviderRestrictPermissionsIgnoresMissingFile() throws IOException {
        new FileLocalStorageProvider(dir.resolve("missing").toFile()).restrictPermissions();
    }

    @Test
    public void multiFileProviderCreatesOwnerOnly() throws IOException {
        MultiFileLocalStorageProvider provider = new MultiFileLocalStorageProvider(dir.toFile());
        provider.save(new byte[]{ 1, 2, 3 });
        provider.save(new byte[]{ 4, 5, 6 });

        List<Path> files = listDir();
        assertEquals(files.size(), 3, files.toString()); // two snapshots + latest
        for (Path file : files) {
            // toRealPath: check the snapshot the "latest" symlink points to
            assertEquals(perms(file.toRealPath()), "rw-------", file.toString());
        }
        assertEquals(provider.load(), new byte[]{ 4, 5, 6 });
    }

    @Test
    public void atomicCopyFallbackCreatesOwnerOnly() throws IOException {
        Path target = worldReadableFile("latest");
        PlatformDependent.writeOwnerOnlyAtomically(target.toFile(), new byte[]{ 1 });

        assertEquals(perms(target), "rw-------");
        assertEquals(Files.readAllBytes(target), new byte[]{ 1 });
        assertEquals(listDir(), List.of(target), "temp file should not be left behind");
    }
}
