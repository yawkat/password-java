package at.yawk.password;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;

public class MultiFileLocalStorageProviderTest {
    private Path dir;

    @BeforeMethod
    public void setUp() throws IOException {
        dir = Files.createTempDirectory("multi-file-storage-test");
    }

    @AfterMethod(alwaysRun = true)
    public void tearDown() throws IOException {
        try (Stream<Path> files = Files.walk(dir)) {
            for (Path p : files.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(p);
            }
        }
    }

    /**
     * A relative directory other than "." must not produce a dangling `latest` link (#27).
     */
    @Test
    public void testRelativeDirectory() throws IOException {
        Path relative = Path.of("").toAbsolutePath().relativize(dir.toAbsolutePath());
        assertFalse(relative.isAbsolute());
        MultiFileLocalStorageProvider provider = new MultiFileLocalStorageProvider(relative.toFile());

        provider.save(new byte[]{ 1, 2, 3 });
        assertEquals(provider.load(), new byte[]{ 1, 2, 3 });
        provider.save(new byte[]{ 4, 5 });
        assertEquals(provider.load(), new byte[]{ 4, 5 });

        // the link target is the bare file name, so it resolves the same with an absolute directory
        Path latest = dir.resolve("latest");
        if (Files.isSymbolicLink(latest)) {
            assertFalse(Files.readSymbolicLink(latest).isAbsolute());
            assertEquals(Files.readSymbolicLink(latest).getNameCount(), 1);
        }
        assertEquals(new MultiFileLocalStorageProvider(new File(dir.toString())).load(), new byte[]{ 4, 5 });
    }
}
