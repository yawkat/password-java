package at.yawk.password.app

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import at.yawk.password.AuthProtocol
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
 * File format: version (1) ‖ slot (1) ‖ length of the URL (2) ‖ server URL (UTF-8) ‖ install salt (32) ‖ GCM nonce (12)
 * ‖ ciphertext with tag. Everything before the nonce is associated data, so it can't be changed without breaking the
 * tag. There are two Keystore keys, one per slot: a new key is made in the other slot, and the old one is only deleted
 * once the new one is stored, so that a cancelled replacement keeps the old key.
 *
 * @param canStore Whether the device has a screen lock and a strong biometric enrolled.
 * @param requireAuthentication Only for tests on devices without a screen lock: a key without the biometric check.
 */
class AndroidOtpKeyStore(
    private val file: File,
    private val alias: String = "otp-vault-key",
    private val requireAuthentication: Boolean = true,
    private val canStore: () -> Boolean = { true },
) : OtpKeyStore {
    private class Header(val slot: Int, val info: StoredKeyInfo, val associatedData: ByteArray)

    private class Content(val header: Header, val nonce: ByteArray, val ciphertext: ByteArray)

    /** The header of [file], read once (a file read and Keystore calls): [keyInfo] is called on the main thread */
    @Volatile
    private var header: Header? = null
    @Volatile
    private var headerRead = false

    private fun keyStore() = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    private fun alias(slot: Int) = "$alias-$slot"

    override fun canStore() = canStore.invoke()

    private fun read(): Content? {
        val bytes = try {
            file.readBytes()
        } catch (e: IOException) {
            return null
        }
        val buffer = ByteBuffer.wrap(bytes)
        if (buffer.remaining() < 4 || buffer.get() != FORMAT_VERSION) return null
        val slot = buffer.get().toInt()
        val urlLength = buffer.getShort().toInt() and 0xffff
        if (slot !in 0..1 || buffer.remaining() < urlLength + AuthProtocol.SALT_LENGTH + NONCE_LENGTH) return null
        val url = ByteArray(urlLength).also { buffer.get(it) }
        val salt = ByteArray(AuthProtocol.SALT_LENGTH).also { buffer.get(it) }
        val associatedData = bytes.copyOf(buffer.position())
        val nonce = ByteArray(NONCE_LENGTH).also { buffer.get(it) }
        val ciphertext = ByteArray(buffer.remaining()).also { buffer.get(it) }
        val info = StoredKeyInfo(url.toString(Charsets.UTF_8), vaultIdOf(salt))
        return Content(Header(slot, info, associatedData), nonce, ciphertext)
    }

    private fun header(): Header? {
        if (!headerRead) {
            header = read()?.header?.takeIf { keyStore().containsAlias(alias(it.slot)) }
            headerRead = true
        }
        return header
    }

    override fun keyInfo(): StoredKeyInfo? = header()?.info

    override suspend fun store(exported: ByteArray, url: String, authenticator: Authenticator): Boolean {
        val urlBytes = url.toByteArray(Charsets.UTF_8)
        require(urlBytes.size <= 0xffff) { "URL too long" }
        val (old, slot, cipher) = withContext(Dispatchers.IO) {
            val old = header()
            val slot = if (old?.slot == 0) 1 else 0
            deleteKey(slot)
            Triple(old, slot, Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, generateKey(slot)) })
        }
        val associatedData = ByteBuffer.allocate(4 + urlBytes.size + AuthProtocol.SALT_LENGTH)
            .put(FORMAT_VERSION).put(slot.toByte()).putShort(urlBytes.size.toShort()).put(urlBytes)
            .put(exported, 0, AuthProtocol.SALT_LENGTH).array()
        val ciphertext = try {
            val authenticated = authenticator.authenticate(cipher, "Enable fingerprint unlock") ?: run {
                withContext(Dispatchers.IO) { deleteKey(slot) }
                return false
            }
            authenticated.updateAAD(associatedData)
            authenticated.doFinal(exported)
        } catch (e: Exception) {
            withContext(Dispatchers.IO) { deleteKey(slot) }
            throw e
        }
        val content = ByteBuffer.allocate(associatedData.size + cipher.iv.size + ciphertext.size)
            .put(associatedData).put(cipher.iv).put(ciphertext).array()
        withContext(Dispatchers.IO) {
            val temp = File(file.parentFile, file.name + ".tmp")
            temp.writeBytes(content)
            if (!temp.renameTo(file)) {
                temp.delete()
                deleteKey(slot)
                throw IOException("Could not write $file")
            }
            header = Header(slot, StoredKeyInfo(url, vaultIdOf(exported)), associatedData)
            headerRead = true
            if (old != null) deleteKey(old.slot)
        }
        return true
    }

    override suspend fun load(authenticator: Authenticator): ByteArray? {
        val (cipher, content) = withContext(Dispatchers.IO) {
            val content = read() ?: throw OtpKeyInvalidatedException()
            val key = keyStore().getKey(alias(content.header.slot), null) as? SecretKey
                ?: throw OtpKeyInvalidatedException()
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
            authenticated.updateAAD(content.header.associatedData)
            authenticated.doFinal(content.ciphertext)
        } catch (e: AEADBadTagException) {
            throw OtpKeyInvalidatedException(e)
        }
    }

    override fun delete() {
        file.delete()
        deleteKey(0)
        deleteKey(1)
        header = null
        headerRead = true
    }

    private fun deleteKey(slot: Int) {
        val keyStore = keyStore()
        if (keyStore.containsAlias(alias(slot))) {
            keyStore.deleteEntry(alias(slot))
        }
    }

    private fun generateKey(slot: Int): SecretKey {
        fun spec(strongBox: Boolean): KeyGenParameterSpec {
            val builder = KeyGenParameterSpec.Builder(
                alias(slot),
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
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
