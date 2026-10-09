package at.yawk.password.app

import at.yawk.password.AuthProtocol
import javax.crypto.Cipher

/**
 * Keeps the exported key of the 2FA vault (`VaultClient.exportKey`) encrypted by a key that only a biometric check
 * releases, so that a fingerprint opens the vault without its password (Android).
 */
interface OtpKeyStore {
    /**
     * Whether this device can keep a key: it has a screen lock and a strong biometric (e.g. a fingerprint) enrolled.
     */
    fun canStore(): Boolean

    /**
     * What the stored key belongs to, or `null` if there is none. The key may still turn out to be invalid when used.
     * It is only used for its server: with another URL, it would sign requests for a server that doesn't have the
     * vault.
     */
    fun keyInfo(): StoredKeyInfo?

    /**
     * Replace the stored key with [exported], the key of the vault on [url], after a biometric check. The old key is
     * only replaced if that succeeds.
     *
     * @return `false` if the user cancelled
     * @throws AuthenticationException if the check failed (e.g. too many attempts)
     */
    suspend fun store(exported: ByteArray, url: String, authenticator: Authenticator): Boolean

    /**
     * The stored key, after a biometric check. The caller wipes it.
     *
     * @return `null` if the user cancelled
     * @throws OtpKeyInvalidatedException if the key can't be used anymore (e.g. the screen lock was removed); it should
     * be deleted
     * @throws AuthenticationException if the check failed
     */
    suspend fun load(authenticator: Authenticator): ByteArray?

    fun delete()
}

/**
 * What a stored key belongs to.
 *
 * @property url The server.
 * @property vaultId The vault on that server: the install salt in the exported key (hex). It is not secret, the server
 * hands it out. A vault that was created again has another one.
 */
data class StoredKeyInfo(val url: String, val vaultId: String)

/**
 * The [StoredKeyInfo.vaultId] of an exported key.
 */
fun vaultIdOf(exported: ByteArray): String =
    exported.copyOf(AuthProtocol.SALT_LENGTH).joinToString("") { "%02x".format(it) }

/**
 * The biometric check that unlocks a [Cipher] of a key that requires it.
 */
fun interface Authenticator {
    /**
     * @return The cipher, now usable, or `null` if the user cancelled
     * @throws AuthenticationException if the check failed
     */
    suspend fun authenticate(cipher: Cipher, title: String): Cipher?
}

class AuthenticationException(message: String) : Exception(message)

class OtpKeyInvalidatedException(cause: Throwable? = null) :
    Exception("The fingerprint key is no longer valid", cause)
