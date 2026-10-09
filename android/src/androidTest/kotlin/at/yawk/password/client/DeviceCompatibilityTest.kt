// In the client's package, for its package-private KeyMaterial, BlobCodec and LegacyBlob
package at.yawk.password.client

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import at.yawk.password.MultiFileLocalStorageProvider
import at.yawk.password.model.DecryptedBlob
import at.yawk.password.model.PasswordBlob
import at.yawk.password.model.PasswordEntry
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
 * Runs the libraries the app relies on (Jackson, BouncyCastle, JCA AES-GCM, java.nio.file) on the device, which catches calls of
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
    fun keyDerivation() {
        // Argon2id, HKDF and Ed25519, same vector as KeyMaterialTest in :client
        val start = System.nanoTime()
        val keys = KeyMaterial.derive("password".toByteArray(), "0".repeat(32).toByteArray())
        Log.i("DeviceCompatibilityTest", "Key derivation took ${(System.nanoTime() - start) / 1_000_000} ms")
        assertEquals(
            "7c9d3f177b79c1cb0310b940a0a790df08eb95c70c24451066e374c987f315ae",
            keys.publicKey.joinToString("") { "%02x".format(it) },
        )
        assertEquals(
            "b041a31fdff0db3ae6ccafe3af276d31e15aad404f46cec09d11e0a0e73144bd" +
                "8a86cb093c3f56407d3553e21e4c17a13cb45ba116f11bfbeece0bdc2830a304",
            keys.sign("hello".toByteArray()).joinToString("") { "%02x".format(it) },
        )
    }

    @Test
    fun blobCodecRoundTrip() {
        val keys = KeyMaterial.derive(password, ByteArray(32))
        val decrypted = DecryptedBlob<PasswordBlob>().apply {
            data = blob("example.com" to "hunter2\nuser")
            revision = 3
        }
        val encrypted = BlobCodec.encrypt(ObjectMapper(), keys, decrypted)
        assertEquals(decrypted, BlobCodec.decrypt(ObjectMapper(), keys, encrypted, PasswordBlob::class.java))
    }

    @Test
    fun readsLegacyFixture() {
        // written by the old desktop client with Jackson 3, see LegacyBlobTest in :client
        val bytes = javaClass.getResourceAsStream("jackson3-db.bin")!!.use { it.readBytes() }
        val entries = LegacyBlob.decrypt(ObjectMapper(), password, bytes).data.passwords
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
    fun clientLoadsAndSavesLocalCopy() {
        // a local copy, as the client leaves it after an unlock
        val keys = KeyMaterial.derive(password, ByteArray(32))
        val decrypted = DecryptedBlob<PasswordBlob>().apply { data = blob("a" to "1") }
        MultiFileLocalStorageProvider(dir).save(BlobCodec.encrypt(ObjectMapper(), keys, decrypted))

        // nothing listens on port 1: the client loads the local copy, saves locally, then fails the upload
        val client = PasswordClient("http://127.0.0.1:1", MultiFileLocalStorageProvider(dir), password)
        val loaded = client.load()
        assertEquals(ClientValue.LocalReason.SERVER_UNAVAILABLE, loaded.localReason)
        assertEquals(listOf("a"), loaded.value!!.passwords.map { it.name })
        try {
            client.save(blob("b" to "2"))
            fail("upload should fail")
        } catch (expected: IOException) {
        }
        val reloaded = PasswordClient("http://127.0.0.1:1", MultiFileLocalStorageProvider(dir), password).load()
        assertEquals(listOf("b"), reloaded.value!!.passwords.map { it.name })
    }
}
