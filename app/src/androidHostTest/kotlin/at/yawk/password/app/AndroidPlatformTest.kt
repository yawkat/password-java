package at.yawk.password.app

import android.content.SharedPreferences
import java.io.File
import java.io.IOException
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AndroidPlatformTest {
    private val filesDir: File = Files.createTempDirectory("files").toFile()
    private val preferences = FakePreferences()
    private val platform = AndroidPlatform(preferences, filesDir)

    @AfterTest
    fun tearDown() {
        filesDir.deleteRecursively()
    }

    @Test
    fun defaults() {
        assertEquals(AppConfig("https://pw.yawk.at", File(filesDir, "db").path), platform.loadConfig())
    }

    @Test
    fun readsOldAppSettings() {
        // the old app stored the URL as "host"; an empty one means the default
        preferences.values["host"] = ""
        assertEquals("https://pw.yawk.at", platform.loadConfig().url)
        preferences.values["host"] = "https://example.com"
        assertEquals("https://example.com", platform.loadConfig().url)
    }

    @Test
    fun savesUrl() {
        platform.saveUrl("https://example.com")
        assertEquals("https://example.com", preferences.values["host"])
        assertEquals("https://example.com", platform.loadConfig().url)

        preferences.failCommit = true
        assertFailsWith<IOException> { platform.saveUrl("https://other.example.com") }
    }

    @Test
    fun storageInFilesDir() {
        val storage = platform.openStorage(platform.loadConfig())
        assertTrue(File(filesDir, "db").isDirectory)
        assertNull(storage.load())
        storage.save(byteArrayOf(1, 2, 3))
        assertNotNull(storage.load())
        assertTrue(File(filesDir, "db/latest").exists())
    }

    /**
     * Just enough of [SharedPreferences] for [AndroidPlatform].
     */
    private class FakePreferences : SharedPreferences {
        val values = mutableMapOf<String, Any?>()
        var failCommit = false

        override fun getAll() = values
        override fun getString(key: String, defValue: String?) = values[key] as String? ?: defValue
        override fun getStringSet(key: String, defValues: MutableSet<String>?) = throw UnsupportedOperationException()
        override fun getInt(key: String, defValue: Int) = throw UnsupportedOperationException()
        override fun getLong(key: String, defValue: Long) = throw UnsupportedOperationException()
        override fun getFloat(key: String, defValue: Float) = throw UnsupportedOperationException()
        override fun getBoolean(key: String, defValue: Boolean) = throw UnsupportedOperationException()
        override fun contains(key: String) = key in values
        override fun registerOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener) =
            throw UnsupportedOperationException()
        override fun unregisterOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener) =
            throw UnsupportedOperationException()

        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            val changes = mutableMapOf<String, Any?>()
            override fun putString(key: String, value: String?) = apply { changes[key] = value }
            override fun putStringSet(key: String, values: MutableSet<String>?) = throw UnsupportedOperationException()
            override fun putInt(key: String, value: Int) = throw UnsupportedOperationException()
            override fun putLong(key: String, value: Long) = throw UnsupportedOperationException()
            override fun putFloat(key: String, value: Float) = throw UnsupportedOperationException()
            override fun putBoolean(key: String, value: Boolean) = throw UnsupportedOperationException()
            override fun remove(key: String) = throw UnsupportedOperationException()
            override fun clear() = throw UnsupportedOperationException()
            override fun apply() {
                commit()
            }

            override fun commit(): Boolean {
                if (failCommit) return false
                values.putAll(changes)
                return true
            }
        }
    }
}
