package at.yawk.password.app

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.security.InvalidKeyException
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Keeps the exported key of the 2FA vault in [file], encrypted with AES-256-GCM by a key in the Android Keystore
 * that needs a strong biometric check for every use. The key survives enrolling another fingerprint (so whoever knows
 * the device PIN can add theirs and open the vault, which is accepted), but not removing the screen lock.
 *
 * File format: version (1) ‖ length of the URL (2) ‖ server URL (UTF-8) ‖ GCM nonce (12) ‖ ciphertext with tag. The
 * URL is associated data, so it can't be changed without breaking the tag.
 *
 * @param requireAuthentication Only for tests on devices without a screen lock: a key without the biometric check.
 */
class AndroidOtpKeyStore(
    private val file: File,
    private val alias: String = "otp-vault-key",
    private val requireAuthentication: Boolean = true,
) : OtpKeyStore {
    private fun keyStore() = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    /**
     * The parsed file: the URL as bytes (the associated data), the nonce and the ciphertext.
     */
    private class Content(val url: ByteArray, val nonce: ByteArray, val ciphertext: ByteArray)

    private fun read(): Content? {
        val bytes = try {
            file.readBytes()
        } catch (e: IOException) {
            return null
        }
        val buffer = ByteBuffer.wrap(bytes)
        if (buffer.remaining() < 3 || buffer.get() != FORMAT_VERSION) return null
        val urlLength = buffer.getShort().toInt() and 0xffff
        if (buffer.remaining() < urlLength + NONCE_LENGTH) return null
        val url = ByteArray(urlLength).also { buffer.get(it) }
        val nonce = ByteArray(NONCE_LENGTH).also { buffer.get(it) }
        val ciphertext = ByteArray(buffer.remaining()).also { buffer.get(it) }
        return Content(url, nonce, ciphertext)
    }

    override fun keyUrl(): String? {
        if (!keyStore().containsAlias(alias)) return null
        return read()?.url?.toString(Charsets.UTF_8)
    }

    override suspend fun store(exported: ByteArray, url: String, authenticator: Authenticator): Boolean {
        val urlBytes = url.toByteArray(Charsets.UTF_8)
        require(urlBytes.size <= 0xffff) { "URL too long" }
        val cipher = withContext(Dispatchers.IO) {
            delete()
            Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, generateKey()) }
        }
        val ciphertext = try {
            val authenticated = authenticator.authenticate(cipher, "Enable fingerprint unlock") ?: run {
                delete()
                return false
            }
            authenticated.updateAAD(urlBytes)
            authenticated.doFinal(exported)
        } catch (e: Exception) {
            delete()
            throw e
        }
        val nonce = cipher.iv
        val content = ByteBuffer.allocate(1 + 2 + urlBytes.size + nonce.size + ciphertext.size)
            .put(FORMAT_VERSION).putShort(urlBytes.size.toShort()).put(urlBytes).put(nonce).put(ciphertext).array()
        withContext(Dispatchers.IO) {
            val temp = File(file.parentFile, file.name + ".tmp")
            temp.writeBytes(content)
            if (!temp.renameTo(file)) {
                temp.delete()
                throw IOException("Could not write $file")
            }
        }
        return true
    }

    override suspend fun load(authenticator: Authenticator): ByteArray? {
        val (cipher, content) = withContext(Dispatchers.IO) {
            val content = read() ?: throw OtpKeyInvalidatedException()
            val key = keyStore().getKey(alias, null) as? SecretKey ?: throw OtpKeyInvalidatedException()
            val cipher = Cipher.getInstance(TRANSFORMATION)
            try {
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, content.nonce))
            } catch (e: KeyPermanentlyInvalidatedException) {
                throw OtpKeyInvalidatedException(e)
            } catch (e: InvalidKeyException) {
                throw OtpKeyInvalidatedException(e)
            }
            cipher to content
        }
        val authenticated = authenticator.authenticate(cipher, "Unlock 2FA codes") ?: return null
        return try {
            authenticated.updateAAD(content.url)
            authenticated.doFinal(content.ciphertext)
        } catch (e: AEADBadTagException) {
            throw OtpKeyInvalidatedException(e)
        }
    }

    override fun delete() {
        file.delete()
        val keyStore = keyStore()
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
    }

    private fun generateKey(): SecretKey {
        fun spec(strongBox: Boolean): KeyGenParameterSpec {
            val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setIsStrongBoxBacked(strongBox)
            if (requireAuthentication) {
                builder.setUserAuthenticationRequired(true)
                    // another fingerprint keeps the key working, see the class comment
                    .setInvalidatedByBiometricEnrollment(false)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    // every use needs a strong biometric check
                    builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                } else {
                    // the same on Android 10: -1 is "for every use, biometric only"
                    @Suppress("DEPRECATION")
                    builder.setUserAuthenticationValidityDurationSeconds(-1)
                }
            }
            return builder.build()
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        return try {
            generator.init(spec(strongBox = true))
            generator.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            generator.init(spec(strongBox = false))
            generator.generateKey()
        }
    }

    private companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val FORMAT_VERSION: Byte = 1
        const val NONCE_LENGTH = 12
        const val TAG_BITS = 128
    }
}
