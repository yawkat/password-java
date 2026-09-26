package at.yawk.password.server;

import io.micronaut.context.ApplicationContext;
import io.micronaut.runtime.server.EmbeddedServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Runs the real server on a random port, with a fresh temporary data directory.
 */
public final class TestServer implements AutoCloseable {
    private final Path dataDirectory;
    private final EmbeddedServer server;

    private TestServer(Path dataDirectory, EmbeddedServer server) {
        this.dataDirectory = dataDirectory;
        this.server = server;
    }

    public static TestServer start() throws IOException {
        Path dataDirectory = Files.createTempDirectory("password-server");
        EmbeddedServer server;
        try {
            server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                    "micronaut.server.host", "127.0.0.1",
                    "micronaut.server.port", -1,
                    DatabaseState.DATA_DIR_PROPERTY, dataDirectory.toString()
            ));
        } catch (RuntimeException e) {
            try {
                deleteRecursively(dataDirectory);
            } catch (IOException | RuntimeException suppressed) {
                e.addSuppressed(suppressed);
            }
            throw e;
        }
        return new TestServer(dataDirectory, server);
    }

    public String getUrl() {
        return "http://127.0.0.1:" + server.getPort();
    }

    @Override
    public void close() {
        server.getApplicationContext().close();
        try {
            deleteRecursively(dataDirectory);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void deleteRecursively(Path directory) throws IOException {
        try (Stream<Path> files = Files.walk(directory)) {
            for (Path file : files.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(file);
            }
        }
    }
}
