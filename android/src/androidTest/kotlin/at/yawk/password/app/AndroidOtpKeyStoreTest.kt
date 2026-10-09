package at.yawk.password.app

import android.app.KeyguardManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import javax.crypto.Cipher
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The Keystore part of the fingerprint unlock, on a device. The biometric prompt itself can't run in a test: the keys
 * here either need no check, or the test shows that they can't be used without one.
 */
@RunWith(AndroidJUnit4::class)
class AndroidOtpKeyStoreTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val file = File(context.cacheDir, "otp-key-test")
    private val exported = ByteArray(64) { it.toByte() }

    private companion object {
        const val URL = "https://pw.example.com"
    }

    /** Passes the check without a prompt, or cancels it */
    private class Passing(val cancel: Boolean = false) : Authenticator {
        override suspend fun authenticate(cipher: Cipher, title: String) = if (cancel) null else cipher
    }

    private fun store(requireAuthentication: Boolean = false) =
        AndroidOtpKeyStore(file, alias = "otp-key-test", requireAuthentication = requireAuthentication)

    @After
    fun tearDown() {
        store().delete()
    }

    @Test
    fun roundTrip() = runBlocking {
        val store = store()
        assertNull(store.keyInfo()?.url)
        assertTrue(store.store(exported, URL, Passing()))
        assertEquals(URL, store.keyInfo()?.url)
        assertArrayEquals(exported, store.load(Passing()))
        // cancelled: nothing returned, the key is kept
        assertNull(store.load(Passing(cancel = true)))
        assertEquals(URL, store.keyInfo()?.url)
        store.delete()
        assertNull(store.keyInfo()?.url)
    }

    @Test
    fun cancelledStoreKeepsNothing() = runBlocking {
        val store = store()
        assertFalse(store.store(exported, URL, Passing(cancel = true)))
        assertNull(store.keyInfo()?.url)
    }

    @Test
    fun tamperedFile() = runBlocking {
        val store = store()
        store.store(exported, URL, Passing())
        val content = file.readBytes()
        content[content.size - 1] = (content[content.size - 1].toInt() xor 1).toByte()
        file.writeBytes(content)
        try {
            store.load(Passing())
            fail("tampered key accepted")
        } catch (e: OtpKeyInvalidatedException) {
            // expected
        }
    }

    /**
     * A replacement that is cancelled keeps the old key working.
     */
    @Test
    fun cancelledReplacementKeepsOldKey() = runBlocking {
        val store = store()
        store.store(exported, URL, Passing())
        val other = ByteArray(64) { (it + 1).toByte() }
        assertFalse(store.store(other, "https://other.example.com", Passing(cancel = true)))
        assertEquals(URL, store.keyInfo()?.url)
        assertArrayEquals(exported, store.load(Passing()))
        // a completed replacement
        assertTrue(store.store(other, "https://other.example.com", Passing()))
        assertEquals("https://other.example.com", store.keyInfo()?.url)
        assertEquals(vaultIdOf(other), store.keyInfo()?.vaultId)
        assertArrayEquals(other, store.load(Passing()))
        // and a new instance reads the same
        assertEquals(store.keyInfo(), store().keyInfo())
    }

    /**
     * The URL is associated data: pointing the key at another server breaks it.
     */
    @Test
    fun changedUrl() = runBlocking {
        val store = store()
        store.store(exported, URL, Passing())
        val content = file.readBytes()
        // "https://pw.example.com" -> "https://pw.example.org", same length
        val text = String(content, Charsets.ISO_8859_1).replace(URL, "https://pw.example.org")
        file.writeBytes(text.toByteArray(Charsets.ISO_8859_1))
        assertEquals("https://pw.example.org", store().keyInfo()?.url)
        try {
            store.load(Passing())
            fail("changed URL accepted")
        } catch (e: OtpKeyInvalidatedException) {
            // expected
        }
    }

    /**
     * The real key needs the biometric check for every use: without one, it encrypts nothing. Needs a screen lock,
     * which the CI emulator doesn't have.
     */
    @Test
    fun keyNeedsAuthentication() {
        // outside of runBlocking, which would turn the skip into a failure
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        assumeTrue("no screen lock", keyguard.isDeviceSecure)
        runBlocking { assertKeyNeedsAuthentication() }
    }

    private suspend fun assertKeyNeedsAuthentication() {
        val store = store(requireAuthentication = true)
        try {
            store.store(exported, URL, Passing())
            fail("the key worked without a biometric check")
        } catch (e: Exception) {
            // UserNotAuthenticatedException, wrapped by the cipher
        }
        assertNull(store.keyInfo()?.url)
    }
}
