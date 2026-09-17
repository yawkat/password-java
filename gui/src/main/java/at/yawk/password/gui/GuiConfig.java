package at.yawk.password.gui;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import lombok.Value;

/**
 * Configuration loaded from {@code $XDG_CONFIG_HOME/password-gui/config.properties}.
 *
 * @author yawkat
 */
@Value
class GuiConfig {
    private static final String DEFAULT_URL = "https://pw.yawk.at";

    private final String url;
    private final File storageDirectory;

    static GuiConfig load() throws IOException {
        Path file = xdgDirectory("XDG_CONFIG_HOME", ".config").resolve("password-gui/config.properties");
        Properties properties = new Properties();
        if (Files.exists(file)) {
            try (Reader reader = Files.newBufferedReader(file)) {
                properties.load(reader);
            }
        }
        String url = properties.getProperty("url", DEFAULT_URL);
        String storageDir = properties.getProperty("storageDir");
        File storage = storageDir == null ?
                xdgDirectory("XDG_DATA_HOME", ".local/share").resolve("password").toFile() :
                new File(storageDir.replaceFirst("^~(?=/|$)", System.getProperty("user.home")));
        return new GuiConfig(url, storage);
    }

    private static Path xdgDirectory(String env, String fallback) {
        String value = System.getenv(env);
        if (value != null && !value.isEmpty()) {
            return Path.of(value);
        }
        return Path.of(System.getProperty("user.home"), fallback);
    }
}
