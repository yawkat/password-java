package at.yawk.password.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import at.yawk.password.LocalStorageProvider
import at.yawk.password.client.ClientValue
import at.yawk.password.client.OtpStore
import at.yawk.password.client.VaultClient
import at.yawk.password.client.VaultKey
import at.yawk.password.client.WrongPasswordException
import at.yawk.password.model.OtpAccount
import at.yawk.password.model.OtpBlob
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

private val log = LoggerFactory.getLogger(OtpViewModel::class.java)

/**
 * How long the unlocked 2FA vault may go without user activity before it locks.
 */
const val OTP_IDLE_LOCK_TIMEOUT_MS = 5 * 60 * 1000L

/**
 * How long the 2FA vault stays unlocked in the background (Android) while the editor or the import has unsaved
 * changes, e.g. to copy a secret from the browser. Without such changes, it locks right away.
 */
const val OTP_BACKGROUND_DRAFT_TIMEOUT_MS = 60 * 1000L

/**
 * Owns the unlocked [OtpStore] of the 2FA vault and exposes it as [state], like [PasswordViewModel] does for the
 * password database. The two are independent: the 2FA vault has its own password, the backup password.
 *
 * All client calls run on [ioDispatcher], serialized by a mutex. The backup password is kept as a byte array only
 * (shared with the client, which needs it to derive keys) and wiped on [lock], on failed unlocks and when the view
 * model is cleared.
 */
class OtpViewModel(
    private val platform: Platform,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val clientFactory: (String, LocalStorageProvider, ByteArray) -> VaultClient<OtpBlob> =
        { url, storage, password -> VaultClient.otp(url, storage, VaultKey.ofPassword(password)) },
    /** Monotonic clock in milliseconds, for the idle lock */
    private val clock: () -> Long = { System.nanoTime() / 1_000_000 },
    private val idleLockTimeoutMs: Long = OTP_IDLE_LOCK_TIMEOUT_MS,
    private val backgroundDraftTimeoutMs: Long = OTP_BACKGROUND_DRAFT_TIMEOUT_MS,
) : ViewModel() {
    private val _state = MutableStateFlow<OtpState>(OtpState.Closed)
    val state: StateFlow<OtpState> = _state.asStateFlow()

    private val mutex = Mutex()

    private var config: AppConfig? = null
    private var store: OtpStore? = null
    private var password: ByteArray? = null
    /** Client waiting for [confirmCreate] */
    private var pendingClient: VaultClient<OtpBlob>? = null

    /**
     * UI state of the unlocked screen (search, open page, drafts). Replaced for every session, so nothing of it
     * outlives a lock.
     */
    var screenState = OtpScreenState()
        private set

    /** Incremented by [lockNow]. An operation that was started in an earlier session discards its result. */
    private var session = 0L

    /** [clock] time of the last user activity while unlocked */
    @Volatile
    private var lastActivity = 0L
    private var idleLock: Job? = null

    /**
     * Show the lock screen of the 2FA vault on the server of [config].
     */
    fun open(config: AppConfig) {
        if (_state.value != OtpState.Closed) return
        this.config = config
        _state.value = OtpState.Locked(config)
    }

    /**
     * Lock and go back to the password database.
     */
    fun close() {
        lockNow()
        _state.value = OtpState.Closed
    }

    fun unlock(password: CharSequence) {
        val locked = _state.value as? OtpState.Locked ?: return
        if (password.isEmpty()) return
        val bytes = encodePassword(password)
        val config = locked.config
        _state.value = OtpState.Unlocking(config)
        val unlockSession = session
        viewModelScope.launch {
            mutex.withLock {
                try {
                    val (client, opened) = withContext(ioDispatcher) {
                        val client = clientFactory(config.url, platform.openOtpStorage(config), bytes)
                        client to OtpStore.open(client)
                    }
                    if (session != unlockSession) {
                        bytes.wipe()
                        return@withLock
                    }
                    this@OtpViewModel.password = bytes
                    if (opened == null) {
                        pendingClient = client
                        _state.value = OtpState.ConfirmCreate(config)
                    } else {
                        showUnlocked(opened, localCopyStatus(opened.localReason) ?: "${opened.accounts.size} accounts loaded")
                    }
                } catch (e: Exception) {
                    log.warn("Unlocking the 2FA vault failed", e)
                    bytes.wipe()
                    if (session == unlockSession) {
                        _state.value = OtpState.Locked(config, unlockErrorMessage(e))
                    }
                }
            }
        }
    }

    /**
     * Create an empty vault, if [repeatedPassword] matches the password given to [unlock].
     */
    fun confirmCreate(repeatedPassword: CharSequence) {
        val confirm = _state.value as? OtpState.ConfirmCreate ?: return
        val client = pendingClient ?: return
        val expected = password ?: return
        val repeated = encodePassword(repeatedPassword)
        val matches = constantTimeEquals(expected, repeated)
        repeated.wipe()
        pendingClient = null
        if (matches) {
            showUnlocked(OtpStore.createEmpty(client), "Created a new, empty 2FA vault")
        } else {
            wipePassword()
            _state.value = OtpState.Locked(confirm.config, "The passwords do not match.")
        }
    }

    fun cancelCreate() {
        val confirm = _state.value as? OtpState.ConfirmCreate ?: return
        pendingClient = null
        wipePassword()
        _state.value = OtpState.Locked(confirm.config)
    }

    fun lock() {
        val unlocked = _state.value as? OtpState.Unlocked ?: return
        if (unlocked.busy) return
        lockNow()
    }

    /**
     * Lock right away, also while unlocking or while an operation runs (its result is then discarded). The password
     * is wiped once a running operation is done. Does nothing while closed or locked.
     */
    fun lockNow() {
        val config = when (_state.value) {
            is OtpState.Unlocking, is OtpState.ConfirmCreate, is OtpState.Unlocked -> config ?: return
            else -> return
        }
        session++
        store = null
        screenState = OtpScreenState()
        pendingClient = null
        idleLock?.cancel()
        idleLock = null
        backgroundLock?.cancel()
        backgroundLock = null
        val password = password
        this.password = null
        _state.value = OtpState.Locked(config)
        if (mutex.tryLock()) {
            try {
                password?.wipe()
            } finally {
                mutex.unlock()
            }
        } else {
            viewModelScope.launch { mutex.withLock { password?.wipe() } }
        }
    }

    /** [clock] time when the app went to the background with unsaved changes, while it is there */
    private var backgroundSince: Long? = null
    private var backgroundLock: Job? = null

    /**
     * The app went to the background (Android): lock right away, or after [backgroundDraftTimeoutMs] if there are
     * unsaved changes, so that they survive a short trip to another app.
     */
    fun onBackground() {
        if (backgroundSince != null) return
        if (_state.value !is OtpState.Unlocked || !screenState.isModified) {
            lockNow()
            return
        }
        backgroundSince = clock()
        backgroundLock = viewModelScope.launch {
            delay(backgroundDraftTimeoutMs)
            lockNow()
        }
    }

    /**
     * The app is in the foreground again. Locks now if it was away for too long: the timer of [onBackground] may not
     * have run while the process was frozen.
     */
    fun onForeground() {
        val since = backgroundSince ?: return
        backgroundSince = null
        backgroundLock?.cancel()
        backgroundLock = null
        if (clock() - since >= backgroundDraftTimeoutMs) {
            lockNow()
        } else {
            onActivity()
        }
    }

    /**
     * The user did something (key press, click, touch): postpones the idle lock.
     */
    fun onActivity() {
        lastActivity = clock()
    }

    private fun startIdleLock() {
        idleLock?.cancel()
        lastActivity = clock()
        idleLock = viewModelScope.launch {
            while (true) {
                val idle = clock() - lastActivity
                if (idle >= idleLockTimeoutMs) {
                    lockNow()
                    return@launch
                }
                delay(idleLockTimeoutMs - idle)
            }
        }
    }

    private fun showUnlocked(store: OtpStore, status: String) {
        this.store = store
        screenState = OtpScreenState()
        _state.value = OtpState.Unlocked(store.accounts, store.localReason, status = StatusMessage(status))
        startIdleLock()
    }

    fun showStatus(text: String) {
        _state.update { if (it is OtpState.Unlocked) it.copy(status = StatusMessage(text)) else it }
    }

    fun dismissError() {
        _state.update { if (it is OtpState.Unlocked) it.copy(error = null) else it }
    }

    /**
     * Add [account], or replace the account with its id.
     *
     * @return Whether it was saved.
     */
    fun save(account: OtpAccount): Deferred<Boolean> {
        val existing = (_state.value as? OtpState.Unlocked)?.accounts?.any { it.id == account.id } == true
        return succeeded(modify(
            success = { "Saved “${accountTitle(account)}”" },
            busyText = "Saving…",
            errorTitle = "Save failed",
        ) { store -> if (existing) store.update(account) else store.add(account) })
    }

    fun delete(account: OtpAccount): Deferred<Boolean> = succeeded(modify(
        success = { "Deleted “${accountTitle(account)}”" },
        busyText = "Saving…",
        errorTitle = "Save failed",
    ) { store -> store.delete(account.id) })

    /**
     * Add the accounts of an import with a single save.
     */
    fun import(accounts: List<OtpAccount>): Deferred<Boolean> = succeeded(modify(
        success = { "Imported ${accounts.size} accounts" },
        busyText = "Saving…",
        errorTitle = "Import failed",
    ) { store -> store.addAll(accounts) })

    fun reload(): Deferred<Boolean> = succeeded(modify(
        success = { store -> localCopyStatus(store.localReason) ?: "Reloaded ${store.accounts.size} accounts" },
        busyText = "Reloading…",
        errorTitle = "Reload failed",
    ) { store -> store.reload() })

    val canPickTextFile: Boolean get() = platform.canPickTextFile

    /**
     * Let the user pick a text file to import (desktop).
     *
     * @return Its content, or `null` if none was picked or it could not be read (then shown as an error).
     */
    suspend fun pickImportFile(): String? = try {
        withContext(ioDispatcher) { platform.pickTextFile() }
    } catch (e: Exception) {
        log.warn("Could not read the import file", e)
        _state.update {
            if (it is OtpState.Unlocked) it.copy(error = ErrorMessage("Import failed", "Could not read the file:\n${e.message ?: e}")) else it
        }
        null
    }

    private fun succeeded(result: Deferred<Unit?>) = viewModelScope.async { result.await() != null }

    private fun modify(
        success: (OtpStore) -> String,
        busyText: String,
        errorTitle: String,
        operation: (OtpStore) -> Unit,
    ): Deferred<Unit?> {
        val unlocked = _state.value as? OtpState.Unlocked
        val store = store
        if (unlocked == null || unlocked.busy || store == null) {
            return viewModelScope.async { null }
        }
        onActivity()
        _state.value = unlocked.copy(busy = true, status = StatusMessage(busyText), error = null)
        val operationSession = session
        return viewModelScope.async {
            mutex.withLock {
                try {
                    withContext(ioDispatcher) { operation(store) }
                    if (session != operationSession) return@withLock null
                    updateUnlocked {
                        it.copy(
                            accounts = store.accounts,
                            localReason = store.localReason,
                            busy = false,
                            status = StatusMessage(success(store)),
                        )
                    }
                    Unit
                } catch (e: Exception) {
                    log.warn(errorTitle, e)
                    if (session != operationSession) return@withLock null
                    updateUnlocked {
                        it.copy(
                            busy = false,
                            status = null,
                            error = ErrorMessage(errorTitle, operationErrorText(e)),
                        )
                    }
                    null
                }
            }
        }
    }

    private inline fun updateUnlocked(f: (OtpState.Unlocked) -> OtpState.Unlocked) {
        _state.update { if (it is OtpState.Unlocked) f(it) else it }
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

    internal companion object {
        fun unlockErrorMessage(e: Exception): String {
            val message = e.message ?: e.toString()
            return when {
                e is WrongPasswordException -> "Wrong password."
                message.contains("response code: 403") ->
                    "The server rejected the password, and no local copy could be opened."
                message.contains("response code: 429") ->
                    "Too many failed attempts: the server refuses logins for a while. Try again later."
                else -> "Could not load the 2FA vault: $message"
            }
        }

        fun operationErrorText(e: Exception): String {
            val message = e.message ?: e.toString()
            return if (e is WrongPasswordException) {
                message
            } else {
                "The change could not be saved to the server:\n$message\n\nIt may have been written to the local " +
                    "copy only. Try again once the server is reachable."
            }
        }

        fun localCopyStatus(reason: ClientValue.LocalReason?): String? = when (reason) {
            null -> null
            ClientValue.LocalReason.SERVER_UNAVAILABLE -> "Server unavailable, loaded local copy"
            ClientValue.LocalReason.SERVER_COPY_INVALID -> "Server copy could not be decrypted, loaded local copy"
            ClientValue.LocalReason.SERVER_COPY_OLDER ->
                "Server copy is older than the local copy (a failed upload, or a rollback), loaded local copy"
            ClientValue.LocalReason.NOT_ON_SERVER -> "Server has no 2FA vault, loaded local copy. Saving uploads it"
            ClientValue.LocalReason.VAULT_RESET -> "The 2FA vault was reset on the server, loaded local copy"
        }
    }
}
