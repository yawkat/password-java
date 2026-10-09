package at.yawk.password.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import at.yawk.password.LocalStorageProvider
import at.yawk.password.client.ClientValue
import at.yawk.password.client.PasswordClient
import at.yawk.password.client.PasswordStore
import at.yawk.password.client.WrongPasswordException
import at.yawk.password.model.PasswordEntry
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
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
 * How long the app may stay in the background (Android) before it locks, discarding unsaved edits. Short absences,
 * e.g. to paste a generated password into a website, keep the database unlocked and the editor as it was.
 */
const val BACKGROUND_LOCK_TIMEOUT_MS = 5 * 60 * 1000L

/**
 * Owns the unlocked [PasswordStore] and exposes the app state as [state].
 *
 * All client calls (key derivation, network, disk) run on [ioDispatcher]. Operations are serialized by a mutex, and while one
 * runs the state is marked [UiState.Unlocked.busy] so the UI refuses further modifications.
 *
 * The master password is kept as a byte array only (shared with the [PasswordClient], which needs it to encrypt on
 * save) and wiped on [lock], on failed unlocks and when the view model is cleared.
 */
class PasswordViewModel(
    private val platform: Platform,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val clientFactory: (String, LocalStorageProvider, ByteArray) -> PasswordClient = ::PasswordClient,
    /** Monotonic clock in milliseconds that keeps running while the device sleeps (Android: elapsedRealtime) */
    private val clock: () -> Long = { System.nanoTime() / 1_000_000 },
    private val backgroundLockTimeoutMs: Long = BACKGROUND_LOCK_TIMEOUT_MS,
) : ViewModel() {
    // Unlocking (with a placeholder config) while the configuration loads
    private val _state = MutableStateFlow<UiState>(UiState.Unlocking(AppConfig("", "")))
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val mutex = Mutex()

    /** Configuration of the current session, to return to on [lock] */
    private var config: AppConfig? = null
    private var store: PasswordStore? = null
    private var password: ByteArray? = null
    /** Status to show instead of the usual one once unlocked, because saving the server URL failed */
    private var urlSaveError: String? = null

    /** Client waiting for [confirmCreate] */
    private var pendingClient: PasswordClient? = null

    /**
     * UI state of the unlocked screen, including an entry being edited. It is kept here rather than in the
     * composition, so that recreating the activity (Android) can't lose unsaved edits, and is replaced for every
     * session, so nothing of it outlives a lock.
     */
    var screenState = MainScreenState()
        private set

    /**
     * Incremented by [lockNow]. An operation that was started in an earlier session discards its result.
     */
    private var session = 0L

    /** [clock] time when the app went to the background, or `null` while it is in the foreground */
    private var backgroundSince: Long? = null
    private var backgroundLock: Job? = null

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
        val unlockSession = session
        viewModelScope.launch {
            mutex.withLock {
                try {
                    val (client, opened) = withContext(ioDispatcher) {
                        val client = clientFactory(config.url, platform.openStorage(config), bytes)
                        client to PasswordStore.open(client)
                    }
                    if (session != unlockSession) {
                        // locked meanwhile
                        bytes.wipe()
                        return@withLock
                    }
                    this@PasswordViewModel.password = bytes
                    this@PasswordViewModel.config = config
                    // only remember a URL that worked, and don't let a failure to do so fail the unlock
                    urlSaveError = if (config.url != locked.config.url) saveUrl(config.url) else null
                    if (opened == null) {
                        pendingClient = client
                        _state.value = UiState.ConfirmCreate(config)
                    } else {
                        showUnlocked(opened, localCopyStatus(opened) ?: "${opened.entries.size} entries loaded")
                    }
                } catch (e: Exception) {
                    log.warn("Unlock failed", e)
                    bytes.wipe()
                    if (session == unlockSession) {
                        _state.value = UiState.Locked(config, unlockErrorMessage(e))
                    }
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
        lockNow()
    }

    /**
     * The app went to the background: lock after [backgroundLockTimeoutMs], unless it comes back before.
     */
    fun onBackground() {
        if (backgroundSince != null) {
            return
        }
        backgroundSince = clock()
        backgroundLock = viewModelScope.launch {
            delay(backgroundLockTimeoutMs)
            lockNow()
        }
    }

    /**
     * The app is in the foreground again. If it was away for [backgroundLockTimeoutMs] or longer, lock now: the timer
     * of [onBackground] may not have run while the process was frozen or the device was asleep. This locks right away,
     * before anything is drawn.
     */
    fun onForeground() {
        val since = backgroundSince ?: return
        backgroundSince = null
        backgroundLock?.cancel()
        backgroundLock = null
        if (clock() - since >= backgroundLockTimeoutMs) {
            lockNow()
        }
    }

    /**
     * Lock right away, also while unlocking or while an operation (saving, reloading) runs, and discard an offered
     * database creation. Unlike [lock], this never refuses.
     *
     * A running operation can't be interrupted (it may be stuck in a network request until that times out). It goes
     * on in the background, and its result is discarded. It still needs the master password (to encrypt what it
     * saves), so the password is wiped once the operation is done; right away if none runs.
     */
    fun lockNow() {
        val config = when (val s = _state.value) {
            is UiState.Unlocking -> s.config
            is UiState.ConfirmCreate -> s.config
            is UiState.Unlocked -> config ?: return
            else -> return
        }
        session++
        store = null
        screenState = MainScreenState()
        pendingClient = null
        val password = password
        this.password = null
        _state.value = UiState.Locked(config)
        if (mutex.tryLock()) {
            try {
                password?.wipe()
            } finally {
                mutex.unlock()
            }
        } else {
            // the mutex is fair, so this runs after the running operation
            viewModelScope.launch { mutex.withLock { password?.wipe() } }
        }
    }

    private suspend fun saveUrl(url: String): String? = try {
        withContext(ioDispatcher) { platform.saveUrl(url) }
        null
    } catch (e: Exception) {
        log.warn("Could not save the server URL", e)
        "Could not save the server URL: ${e.message ?: e}"
    }

    private fun showUnlocked(store: PasswordStore, status: String) {
        this.store = store
        screenState = MainScreenState()
        _state.value = UiState.Unlocked(
            entries = store.entries,
            fromLocalStorage = store.isFromLocalStorage,
            status = StatusMessage(urlSaveError ?: status),
        )
        urlSaveError = null
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
            success = { store -> localCopyStatus(store) ?: "Reloaded ${store.entries.size} entries" },
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
        val operationSession = session
        return viewModelScope.async {
            mutex.withLock {
                try {
                    val result = withContext(ioDispatcher) { operation(store) }
                    if (session != operationSession) {
                        // locked meanwhile
                        return@withLock null
                    }
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
                    if (session != operationSession) {
                        return@withLock null
                    }
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
                e is WrongPasswordException -> "Wrong password."
                message.contains("response code: 403") ->
                    "The server rejected the password, and no local copy could be opened."
                message.contains("response code: 429") ->
                    "Too many failed attempts: the server refuses logins for a while. Try again later."
                else -> "Could not load the database: $message"
            }
        }

        /**
         * Why the store shows the local copy, or `null` if it shows the server copy.
         */
        fun localCopyStatus(store: PasswordStore): String? = when (store.localReason) {
            null -> null
            ClientValue.LocalReason.SERVER_UNAVAILABLE -> "Server unavailable, loaded local copy"
            ClientValue.LocalReason.SERVER_COPY_INVALID -> "Server copy could not be decrypted, loaded local copy"
            ClientValue.LocalReason.SERVER_COPY_OLDER ->
                "Server copy is older than the local copy (a failed upload, or a rollback), loaded local copy"
            ClientValue.LocalReason.NOT_ON_SERVER -> "Server has no database, loaded local copy. Saving uploads it"
            ClientValue.LocalReason.VAULT_RESET -> "The database was reset on the server, loaded local copy"
        }

        fun saveErrorText(message: String) =
            "The change could not be saved to the server:\n$message\n\n" +
                "It may have been written to the local backup only. Your change has been kept here, " +
                "try again once the server is reachable."
    }
}
