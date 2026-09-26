package at.yawk.password.app

import at.yawk.password.LocalStorageProvider
import at.yawk.password.MultiFileLocalStorageProvider
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Properties

/**
 * Desktop settings and storage, compatible with the old Qt GUI: the configuration is read from
 * `$XDG_CONFIG_HOME/password-gui/config.properties` (keys `url` and `storageDir`), and the local copy of the
 * database is kept by a [MultiFileLocalStorageProvider] in `storageDir`, by default `$XDG_DATA_HOME/password`.
 */
class DesktopPlatform(
    private val env: (String) -> String? = System::getenv,
    private val home: String = System.getProperty("user.home"),
) : Platform {
    val configFile: Path get() = xdgDirectory("XDG_CONFIG_HOME", ".config").resolve("password-gui/config.properties")

    private fun readProperties(): Properties {
        val properties = Properties()
        val file = configFile
        if (Files.exists(file)) {
            Files.newBufferedReader(file).use { properties.load(it) }
        }
        return properties
    }

    override fun loadConfig(): AppConfig {
        val properties = readProperties()
        val url = properties.getProperty("url", DEFAULT_URL)
        val storageDir = properties.getProperty("storageDir")
        val storage = if (storageDir == null) {
            xdgDirectory("XDG_DATA_HOME", ".local/share").resolve("password").toFile()
        } else {
            File(storageDir.replaceFirst(Regex("^~(?=/|$)"), Regex.escapeReplacement(home)))
        }
        return AppConfig(url, storage.path)
    }

    override fun saveUrl(url: String) {
        val properties = readProperties()
        properties.setProperty("url", url)
        val file = configFile
        Files.createDirectories(file.parent)
        Files.newBufferedWriter(file).use { properties.store(it, "password-gui configuration") }
    }

    override fun openStorage(config: AppConfig): LocalStorageProvider {
        val directory = File(config.storageDirectory)
        if (!directory.isDirectory) {
            Files.createDirectories(
                directory.toPath(),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
            )
        }
        return MultiFileLocalStorageProvider(directory)
    }

    private fun xdgDirectory(variable: String, fallback: String): Path {
        val value = env(variable)
        return if (!value.isNullOrEmpty()) Path.of(value) else Path.of(home, fallback)
    }

    companion object {
        const val DEFAULT_URL = "https://pw.yawk.at"
    }
}
