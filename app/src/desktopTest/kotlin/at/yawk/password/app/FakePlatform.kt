package at.yawk.password.app

import at.yawk.password.LocalStorageProvider
import at.yawk.password.MemoryStorageProvider

class FakePlatform(
    var config: AppConfig,
    var storage: LocalStorageProvider,
    var otpStorage: LocalStorageProvider = MemoryStorageProvider(),
) : Platform {
    var configError: Exception? = null
    var saveError: Exception? = null
    val savedUrls = mutableListOf<String>()

    override fun loadConfig(): AppConfig {
        configError?.let { throw it }
        return config
    }

    override fun saveUrl(url: String) {
        saveError?.let { throw it }
        savedUrls += url
        config = config.copy(url = url)
    }

    override fun openStorage(config: AppConfig) = storage

    override fun openOtpStorage(config: AppConfig) = otpStorage

    /** What [pickTextFile] returns */
    var textFile: String? = null

    override val canPickTextFile get() = true

    override fun pickTextFile() = textFile

    override var otpKeyStore: OtpKeyStore? = null
}
