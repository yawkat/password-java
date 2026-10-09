package at.yawk.password.app

import javax.crypto.Cipher

/**
 * Keeps the key in memory; the biometric check is the [Authenticator] alone.
 */
class FakeOtpKeyStore : OtpKeyStore {
    var key: ByteArray? = null
    var url: String? = null
    /** Makes [load] fail like a key that the Keystore invalidated */
    var invalidated = false

    var canStore = true

    override fun canStore() = canStore

    override fun keyInfo() = key?.let { StoredKeyInfo(url ?: "", vaultIdOf(it)) }

    override suspend fun store(exported: ByteArray, url: String, authenticator: Authenticator): Boolean {
        // like the real one: the old key stays if the check is cancelled
        authenticator.authenticate(Cipher.getInstance("AES/GCM/NoPadding"), "store") ?: return false
        key = exported.copyOf()
        this.url = url
        return true
    }

    override suspend fun load(authenticator: Authenticator): ByteArray? {
        if (invalidated) throw OtpKeyInvalidatedException()
        val key = key ?: throw OtpKeyInvalidatedException()
        authenticator.authenticate(Cipher.getInstance("AES/GCM/NoPadding"), "load") ?: return null
        return key.copyOf()
    }

    override fun delete() {
        key = null
        url = null
    }
}

/**
 * Passes the check, or cancels it while [cancel] is set; counts the checks.
 */
class FakeAuthenticator : Authenticator {
    var cancel = false
    var count = 0

    override suspend fun authenticate(cipher: Cipher, title: String): Cipher? {
        count++
        return if (cancel) null else cipher
    }
}
