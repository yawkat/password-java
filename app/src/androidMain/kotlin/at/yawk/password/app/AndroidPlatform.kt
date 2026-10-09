package at.yawk.password.app

import android.content.Context
import android.content.SharedPreferences
import at.yawk.password.LocalStorageProvider
import at.yawk.password.MultiFileLocalStorageProvider
import java.io.File
import java.io.IOException

/**
 * Android settings and storage, compatible with the old app (github.com/yawkat/password-android): the server URL is
 * kept under `host` in the default shared preferences, and the local copy of the database in `filesDir/db`, which is
 * private to the app.
 */
class AndroidPlatform(
    private val preferences: SharedPreferences,
    private val filesDir: File,
) : Platform {
    constructor(context: Context) : this(
        // what PreferenceManager.getDefaultSharedPreferences, which the old app used, opens
        context.getSharedPreferences("${context.packageName}_preferences", Context.MODE_PRIVATE),
        context.filesDir,
    )

    override fun loadConfig() = AppConfig(
        url = preferences.getString(KEY_URL, null)?.takeIf { it.isNotBlank() } ?: DEFAULT_URL,
        storageDirectory = File(filesDir, "db").path,
    )

    override fun saveUrl(url: String) {
        if (!preferences.edit().putString(KEY_URL, url).commit()) {
            throw IOException("Could not write the settings")
        }
    }

    override fun openStorage(config: AppConfig): LocalStorageProvider = openDirectory(File(config.storageDirectory))

    /**
     * `filesDir/totp`, also private to the app.
     */
    override fun openOtpStorage(config: AppConfig): LocalStorageProvider = openDirectory(File(filesDir, "totp"))

    /**
     * The key behind the fingerprint, in `filesDir/totp-key` (encrypted by the Android Keystore).
     */
    override val otpKeyStore: OtpKeyStore by lazy { AndroidOtpKeyStore(File(filesDir, "totp-key")) }

    private fun openDirectory(directory: File): LocalStorageProvider {
        if (!directory.isDirectory && !directory.mkdirs()) {
            throw IOException("Could not create $directory")
        }
        return MultiFileLocalStorageProvider(directory)
    }

    companion object {
        const val DEFAULT_URL = "https://pw.yawk.at"
        private const val KEY_URL = "host"
    }
}
