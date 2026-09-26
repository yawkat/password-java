package at.yawk.password.app

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Properties
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.writeText
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DesktopPlatformTest {
    private lateinit var dir: Path

    @BeforeTest
    fun setUp() {
        dir = Files.createTempDirectory("platform-test")
    }

    @AfterTest
    fun tearDown() {
        dir.toFile().deleteRecursively()
    }

    @Test
    fun defaultsFollowXdg() {
        val env = mapOf("XDG_CONFIG_HOME" to "$dir/config", "XDG_DATA_HOME" to "$dir/data")
        val config = DesktopPlatform(env::get, home = "$dir/home").loadConfig()
        assertEquals(AppConfig("https://pw.yawk.at", "$dir/data/password"), config)
    }

    @Test
    fun defaultsWithoutXdg() {
        val config = DesktopPlatform({ null }, home = "$dir/home").loadConfig()
        assertEquals(AppConfig("https://pw.yawk.at", "$dir/home/.local/share/password"), config)
    }

    @Test
    fun readsOldGuiConfigAndKeepsStorageDirOnSave() {
        val env = mapOf("XDG_CONFIG_HOME" to "$dir/config")
        val file = dir.resolve("config/password-gui/config.properties")
        file.parent.createDirectories()
        file.writeText("url=http://example.com\nstorageDir=~/pw\n")
        val platform = DesktopPlatform(env::get, home = "$dir/home")
        assertEquals(AppConfig("http://example.com", "$dir/home/pw"), platform.loadConfig())

        platform.saveUrl("http://other.example.com")
        assertEquals(AppConfig("http://other.example.com", "$dir/home/pw"), platform.loadConfig())
        val properties = Properties().apply { Files.newBufferedReader(file).use { load(it) } }
        assertEquals("~/pw", properties.getProperty("storageDir"))
    }

    @Test
    fun storageDirectoryIsCreatedPrivate() {
        val platform = DesktopPlatform({ null }, home = "$dir/home")
        val storageDir = dir.resolve("data/password")
        val storage = platform.openStorage(AppConfig("x", storageDir.toString()))
        assertTrue(storageDir.exists())
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(storageDir)))
        assertNull(storage.load())
        storage.save(byteArrayOf(1, 2, 3))
        assertTrue(storageDir.resolve("latest").exists())
    }
}
