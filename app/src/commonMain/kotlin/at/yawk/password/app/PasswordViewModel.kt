package at.yawk.password.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import at.yawk.password.LocalStorageProvider
import at.yawk.password.client.PasswordClient
import at.yawk.password.client.PasswordStore
import at.yawk.password.model.PasswordEntry
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(PasswordViewModel::class.java)

/**
 * Owns the unlocked [PasswordStore] and exposes the app state as [state].
 *
 * All client calls (scrypt, network, disk) run on [ioDispatcher]. Operations are serialized by a mutex, and while one
 * runs the state is marked [UiState.Unlocked.busy] so the UI refuses further modifications.
 *
 * The master password is kept as a byte array only (shared with the [PasswordClient], which needs it to encrypt on
 * save) and wiped on [lock], on failed unlocks and when the view model is cleared.
 */
class PasswordViewModel(
    private val platform: Platform,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val clientFactory: (String, LocalStorageProvider, ByteArray) -> PasswordClient = ::PasswordClient,
) : ViewModel() {
    // Unlocking (with a placeholder config) while the configuration loads
    private val _state = MutableStateFlow<UiState>(UiState.Unlocking(AppConfig("", "")))
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val mutex = Mutex()

    /** Configuration of the current session, to return to on [lock] */
    private var config: AppConfig? = null
    private var store: PasswordStore? = null
    private var password: ByteArray? = null
    /** Client waiting for [confirmCreate] */
    private var pendingClient: PasswordClient? = null

    init {
        viewModelScope.launch {
            _state.value = try {
                UiState.Locked(withContext(ioDispatcher) { platform.loadConfig() })
            } catch (e: Exception) {
                log.warn("Could not read configuration", e)
                UiState.Error("Could not read configuration: $e")
            }
        }
    }

    /**
     * Derive the keys from [password] and load the database from [url] (or the local copy). The caller should wipe
     * its own copy of the password afterwards; this method keeps an encoded copy only.
     */
    fun unlock(url: String, password: CharSequence) {
        val locked = _state.value as? UiState.Locked ?: return
        if (password.isEmpty()) {
            return
        }
        val bytes = encodePassword(password)
        val config = locked.config.copy(url = url.trim().ifEmpty { locked.config.url })
        _state.value = UiState.Unlocking(config)
        viewModelScope.launch {
            mutex.withLock {
                try {
                    val (client, opened) = withContext(ioDispatcher) {
                        if (config.url != locked.config.url) {
                            platform.saveUrl(config.url)
                        }
                        val client = clientFactory(config.url, platform.openStorage(config), bytes)
                        client to PasswordStore.open(client)
                    }
                    this@PasswordViewModel.password = bytes
                    this@PasswordViewModel.config = config
                    if (opened == null) {
                        pendingClient = client
                        _state.value = UiState.ConfirmCreate(config)
                    } else {
                        showUnlocked(opened, "${opened.entries.size} entries loaded")
                    }
                } catch (e: Exception) {
                    log.warn("Unlock failed", e)
                    bytes.wipe()
                    _state.value = UiState.Locked(config, unlockErrorMessage(e))
                }
            }
        }
    }

    /**
     * Create an empty database, if [repeatedPassword] matches the password given to [unlock].
     */
    fun confirmCreate(repeatedPassword: CharSequence) {
        val confirm = _state.value as? UiState.ConfirmCreate ?: return
        val client = pendingClient ?: return
        val expected = password ?: return
        val repeated = encodePassword(repeatedPassword)
        val matches = constantTimeEquals(expected, repeated)
        repeated.wipe()
        pendingClient = null
        if (matches) {
            showUnlocked(PasswordStore.createEmpty(client), "Created a new, empty database")
        } else {
            wipePassword()
            _state.value = UiState.Locked(confirm.config, "The passwords do not match.")
        }
    }

    fun cancelCreate() {
        val confirm = _state.value as? UiState.ConfirmCreate ?: return
        pendingClient = null
        wipePassword()
        _state.value = UiState.Locked(confirm.config)
    }

    /**
     * Forget the database and the master password.
     */
    fun lock() {
        val unlocked = _state.value as? UiState.Unlocked ?: return
        if (unlocked.busy) {
            return
        }
        _state.value = unlocked.copy(busy = true)
        viewModelScope.launch {
            mutex.withLock {
                store = null
                wipePassword()
                _state.value = UiState.Locked(config!!)
            }
        }
    }

    private fun showUnlocked(store: PasswordStore, status: String) {
        this.store = store
        _state.value = UiState.Unlocked(
            entries = store.entries,
            fromLocalStorage = store.isFromLocalStorage,
            status = StatusMessage(status),
        )
    }

    /**
     * Once the data came from the offline copy, saving must be confirmed because it replaces the server copy.
     */
    fun confirmOfflineSave() {
        _state.update { if (it is UiState.Unlocked) it.copy(offlineSaveConfirmed = true) else it }
    }

    fun showStatus(text: String) {
        _state.update { if (it is UiState.Unlocked) it.copy(status = StatusMessage(text)) else it }
    }

    fun dismissError() {
        _state.update { if (it is UiState.Unlocked) it.copy(error = null) else it }
    }

    /**
     * Add an entry ([old] == null) or replace [old].
     *
     * @return The saved entry, or `null` if saving failed (the error is then in the state) or was refused because
     * another operation is running.
     */
    fun save(old: PasswordEntry?, name: String, value: String): Deferred<PasswordEntry?> = modify(
        success = { if (old == null) "Created “$name”" else "Saved “$name”" },
        busyText = "Saving…",
        errorTitle = "Save failed",
        errorText = ::saveErrorText,
    ) { store -> if (old == null) store.add(name, value) else store.update(old, name, value) }

    /**
     * @return Whether the entry was deleted.
     */
    fun delete(entry: PasswordEntry): Deferred<Boolean> {
        val result = modify(
            success = { "Deleted “${entry.name}”" },
            busyText = "Saving…",
            errorTitle = "Save failed",
            errorText = ::saveErrorText,
        ) { store -> store.delete(entry) }
        return viewModelScope.async { result.await() != null }
    }

    /**
     * Load the database again from the server (or the local copy, if the server is unreachable).
     *
     * @return Whether reloading succeeded.
     */
    fun reload(): Deferred<Boolean> {
        val result = modify(
            success = { store ->
                if (store.isFromLocalStorage) "Server unreachable, loaded local copy"
                else "Reloaded ${store.entries.size} entries"
            },
            busyText = "Reloading…",
            errorTitle = "Reload failed",
            errorText = { "Could not reload the database:\n$it" },
            resetOfflineConfirmation = true,
        ) { store -> store.reload() }
        return viewModelScope.async { result.await() != null }
    }

    private fun <T : Any> modify(
        success: (PasswordStore) -> String,
        busyText: String,
        errorTitle: String,
        errorText: (String) -> String,
        resetOfflineConfirmation: Boolean = false,
        operation: (PasswordStore) -> T,
    ): Deferred<T?> {
        val unlocked = _state.value as? UiState.Unlocked
        val store = store
        if (unlocked == null || unlocked.busy || store == null) {
            return viewModelScope.async { null }
        }
        _state.value = unlocked.copy(busy = true, status = StatusMessage(busyText), error = null)
        return viewModelScope.async {
            mutex.withLock {
                try {
                    val result = withContext(ioDispatcher) { operation(store) }
                    updateUnlocked {
                        it.copy(
                            entries = store.entries,
                            fromLocalStorage = store.isFromLocalStorage,
                            busy = false,
                            offlineSaveConfirmed = if (resetOfflineConfirmation) false else it.offlineSaveConfirmed,
                            status = StatusMessage(success(store)),
                        )
                    }
                    result
                } catch (e: Exception) {
                    log.warn("$errorTitle", e)
                    updateUnlocked {
                        it.copy(busy = false, status = null, error = ErrorMessage(errorTitle, errorText(e.message ?: e.toString())))
                    }
                    null
                }
            }
        }
    }

    private inline fun updateUnlocked(f: (UiState.Unlocked) -> UiState.Unlocked) {
        _state.update { if (it is UiState.Unlocked) f(it) else it }
    }

    private fun wipePassword() {
        password?.wipe()
        password = null
    }

    override fun onCleared() {
        store = null
        pendingClient = null
        wipePassword()
    }

    private companion object {
        fun unlockErrorMessage(e: Exception): String {
            val message = e.message ?: e.toString()
            return when {
                message.startsWith("Invalid HMAC") -> "Wrong password."
                message.contains("response code: 403") ->
                    "The server rejected the password, and no local copy could be opened."
                else -> "Could not load the database: $message"
            }
        }

        fun saveErrorText(message: String) =
            "The change could not be saved to the server:\n$message\n\n" +
                "It may have been written to the local backup only. Your change has been kept here, " +
                "try again once the server is reachable."
    }
}
