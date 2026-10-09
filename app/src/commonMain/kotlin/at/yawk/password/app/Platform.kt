package at.yawk.password.app

import at.yawk.password.LocalStorageProvider

/**
 * Settings of the app. On desktop these come from `$XDG_CONFIG_HOME/password-gui/config.properties`.
 *
 * @property url Base URL of the password server.
 * @property storageDirectory Where the local copy of the database lives, shown to the user and passed back to
 * [Platform.openStorage].
 */
data class AppConfig(val url: String, val storageDirectory: String)

/**
 * Platform-specific persistence: settings and the local copy of the database. Implementations may block; they are
 * only called off the UI thread.
 */
interface Platform {
    /**
     * @throws Exception if the configuration cannot be read
     */
    fun loadConfig(): AppConfig

    /**
     * Remember a changed server URL for the next start.
     */
    fun saveUrl(url: String)

    /**
     * Open the local copy of the database, creating its location if necessary.
     */
    fun openStorage(config: AppConfig): LocalStorageProvider

    /**
     * Open the local copy of the 2FA vault, creating its location if necessary.
     */
    fun openOtpStorage(config: AppConfig): LocalStorageProvider

    /**
     * Whether [pickTextFile] can be used.
     */
    val canPickTextFile: Boolean get() = false

    /**
     * Let the user choose a text file, for an import.
     *
     * @return The content of the file, or `null` if the user chose none
     * @throws Exception if the file can't be read
     */
    fun pickTextFile(): String? = null

    /**
     * Where the key for opening the 2FA vault with a fingerprint is kept, or `null` if the platform has none.
     */
    val otpKeyStore: OtpKeyStore? get() = null
}

/**
 * Clipboard for secrets. A copied secret is removed again after [clearAfterSeconds], but only if the clipboard still
 * holds it.
 */
interface SecretClipboard {
    val clearAfterSeconds: Int

    /**
     * @return `false` if the clipboard is unavailable right now (e.g. another application holds it)
     */
    fun copySecret(text: String): Boolean

    /**
     * Clear the clipboard now if it still holds the last secret we copied. Called on exit.
     */
    fun clearIfOurs()
}
