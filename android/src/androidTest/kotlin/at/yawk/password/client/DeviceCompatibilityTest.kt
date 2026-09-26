// In the client's package, for its package-private AesCodec
package at.yawk.password.client

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import at.yawk.password.MultiFileLocalStorageProvider
import at.yawk.password.model.DecryptedBlob
import at.yawk.password.model.EncryptedBlob
import at.yawk.password.model.PasswordBlob
import at.yawk.password.model.PasswordEntry
import at.yawk.password.model.ScryptParameters
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.File
import java.io.IOException
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs the libraries the app relies on (Jackson, BouncyCastle, java.nio.file) on the device, which catches calls of
 * JDK methods that its Android version lacks: those only fail at runtime there. CI runs this on the oldest supported
 * version (API 29).
 */
@RunWith(AndroidJUnit4::class)
class DeviceCompatibilityTest {
    private val password = "fixture-password".toByteArray()
    private val dir: File = File(
        InstrumentationRegistry.getInstrumentation().targetContext.cacheDir,
        "compat-test-${System.nanoTime()}",
    ).apply { mkdirs() }

    @After
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun blob(vararg entries: Pair<String, String>) = PasswordBlob().apply {
        for ((name, value) in entries) {
            val entry = PasswordEntry()
            entry.name = name
            entry.value = value
            passwords.add(entry)
        }
    }

    @Test
    fun scrypt() {
        // RFC 7914, section 12
        val key = ScryptParameters(10, 8, 16, 64, "NaCl".toByteArray()).runScrypt("password".toByteArray())
        assertEquals(
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
            key.joinToString("") { "%02x".format(it) },
        )
    }

    @Test
    fun aesCodecRoundTrip() {
        val mapper = ObjectMapper()
        val decrypted = DecryptedBlob().apply { data = blob("example.com" to "hunter2\nuser") }
        val encrypted = EncryptedBlob().apply { read(AesCodec.encrypt(mapper, password, decrypted).write()) }
        assertEquals(decrypted, AesCodec.decrypt(ObjectMapper(), password, encrypted))
    }

    @Test
    fun readsJackson3Fixture() {
        // written by the desktop client with Jackson 3, see JacksonCompatibilityTest in :client
        val bytes = javaClass.getResourceAsStream("jackson3-db.bin")!!.use { it.readBytes() }
        val encrypted = EncryptedBlob().apply { read(bytes) }
        val entries = AesCodec.decrypt(ObjectMapper(), password, encrypted).data.passwords
        assertEquals(listOf("example.com", "Bänk 🔑", "empty"), entries.map { it.name })
        assertEquals("pässwörd€\t\u0001", entries[1].value)
    }

    @Test
    fun localStorage() {
        val storage = MultiFileLocalStorageProvider(dir)
        storage.save(byteArrayOf(1, 2, 3))
        assertArrayEquals(byteArrayOf(1, 2, 3), storage.load())
        assertTrue(File(dir, "latest").exists())
    }

    @Test
    fun clientSavesAndLoadsLocalCopy() {
        // nothing listens on port 1: the client saves locally, then fails the upload, and loads the local copy
        val client = PasswordClient("http://127.0.0.1:1", MultiFileLocalStorageProvider(dir), password)
        try {
            client.save(blob("a" to "1"))
            fail("upload should fail")
        } catch (expected: IOException) {
        }
        val loaded = PasswordClient("http://127.0.0.1:1", MultiFileLocalStorageProvider(dir), password).load()
        assertTrue(loaded.isFromLocalStorage)
        assertEquals(listOf("a"), loaded.value!!.passwords.map { it.name })
    }
}
