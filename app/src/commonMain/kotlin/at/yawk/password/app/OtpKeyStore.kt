package at.yawk.password.app

import javax.crypto.Cipher

/**
 * Keeps the exported key of the 2FA vault (`VaultClient.exportKey`) encrypted by a key that only a biometric check
 * releases, so that a fingerprint opens the vault without its password (Android).
 */
interface OtpKeyStore {
    /**
     * The server URL of the stored key, or `null` if there is none. The key may still turn out to be invalid when
     * used. It is only used for this server: with another URL, it would sign requests for a server that doesn't have
     * the vault.
     */
    fun keyUrl(): String?

    /**
     * Replace the stored key with [exported], the key of the vault on [url], after a biometric check.
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
