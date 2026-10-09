package at.yawk.password.app

import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import at.yawk.password.MemoryStorageProvider
import at.yawk.password.client.ClientValue
import at.yawk.password.client.VaultClient
import at.yawk.password.client.VaultKey
import at.yawk.password.model.OtpAccount
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

class OtpViewModelTest {
    private lateinit var server: FakeServer
    private lateinit var platform: FakePlatform
    private lateinit var config: AppConfig
    private val stores = mutableListOf<ViewModelStore>()

    /** Every password array handed to a client, to check that they get wiped */
    private val passwords = mutableListOf<ByteArray>()

    @BeforeTest
    fun setUp() {
        server = FakeServer()
        config = AppConfig(server.url, "/nonexistent")
        platform = FakePlatform(config, MemoryStorageProvider())
    }

    @AfterTest
    fun tearDown() {
        stores.forEach { it.clear() }
        stores.clear()
        server.close()
    }

    private fun newViewModel(
        idleLockTimeoutMs: Long = OTP_IDLE_LOCK_TIMEOUT_MS,
        backgroundDraftTimeoutMs: Long = OTP_BACKGROUND_DRAFT_TIMEOUT_MS,
    ): OtpViewModel {
        val store = ViewModelStore().also { stores += it }
        val factory = viewModelFactory {
            initializer {
                OtpViewModel(
                    platform,
                    clientFactory = { url, storage, password ->
                        passwords += password
                        VaultClient.otp(url, storage, VaultKey.ofPassword(password))
                    },
                    idleLockTimeoutMs = idleLockTimeoutMs,
                    backgroundDraftTimeoutMs = backgroundDraftTimeoutMs,
                )
            }
        }
        return ViewModelProvider.create(store, factory)[OtpViewModel::class]
    }

    private fun OtpViewModel.await(predicate: (OtpState) -> Boolean): OtpState = runBlocking {
        withTimeout(120_000) { state.first(predicate) }
    }

    private inline fun <reified T : OtpState> OtpViewModel.await(): T = await { it is T } as T

    private fun OtpViewModel.awaitIdle(): OtpState.Unlocked =
        await { it is OtpState.Unlocked && !it.busy } as OtpState.Unlocked

    /**
     * Locking wipes the password once a running operation is done, which may be a moment after the state changed:
     * the unlock that is just finishing holds the lock while it publishes the unlocked state.
     */
    private fun assertWipedSoon(password: ByteArray, message: String) {
        val deadline = System.nanoTime() + 10_000_000_000L
        while (!password.all { it == 0.toByte() } && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        assertTrue(password.all { it == 0.toByte() }, message)
    }

        private fun account(issuer: String) = OtpAccount().apply {
        this.issuer = issuer
        secret = "JBSWY3DPEHPK3PXP"
        backupCodes = "code-$issuer"
    }

    private fun OtpViewModel.create(password: String) {
        open(config)
        unlock(password)
        await<OtpState.ConfirmCreate>()
        confirmCreate(password)
        await<OtpState.Unlocked>()
    }

    @Test
    fun createEditAndReopen() {
        val vm = newViewModel()
        assertEquals(OtpState.Closed, vm.state.value)
        vm.open(config)
        vm.await<OtpState.Locked>()

        // no vault: offer to create one, but only with the same password
        vm.unlock("backup")
        vm.await<OtpState.ConfirmCreate>()
        vm.confirmCreate("other")
        assertEquals("The passwords do not match.", vm.await<OtpState.Locked>().error)
        assertTrue(passwords.last().all { it == 0.toByte() }, "password wiped after mismatch")

        vm.unlock("backup")
        vm.await<OtpState.ConfirmCreate>()
        vm.confirmCreate("backup")
        assertTrue(vm.await<OtpState.Unlocked>().accounts.isEmpty())
        assertNull(server.totpDb.get(), "nothing saved before the first modification")

        val github = account("GitHub")
        assertTrue(runBlocking { vm.save(github).await() })
        // an edit replaces the account with the same id
        val renamed = account("GitHub2").apply { id = github.id }
        assertTrue(runBlocking { vm.save(renamed).await() })
        assertTrue(runBlocking { vm.import(listOf(account("A"), account("B"))).await() })
        assertTrue(runBlocking { vm.delete(vm.awaitIdle().accounts.first { it.issuer == "A" }).await() })
        val edited = vm.awaitIdle()
        assertEquals(listOf("GitHub2", "B"), edited.accounts.map { it.issuer })
        assertEquals("Deleted “A”", edited.status?.text)
        assertNotNull(server.totpDb.get())
        assertNull(server.db.get(), "the password database is untouched")
        assertNotNull(platform.otpStorage.load(), "local copy written")

        assertTrue(runBlocking { vm.reload().await() })
        assertEquals("Reloaded 2 accounts", vm.awaitIdle().status?.text)

        val sessionPassword = passwords.last()
        vm.lock()
        vm.await<OtpState.Locked>()
        assertWipedSoon(sessionPassword, "password wiped on lock")

        // another device
        platform.otpStorage = MemoryStorageProvider()
        val other = newViewModel()
        other.open(config)
        other.unlock("backup")
        val reopened = other.await<OtpState.Unlocked>()
        assertEquals(listOf("GitHub2", "B"), reopened.accounts.map { it.issuer })
        assertEquals("code-B", reopened.accounts[1].backupCodes)
        assertNull(reopened.localReason)

        other.close()
        assertEquals(OtpState.Closed, other.state.value)
        assertWipedSoon(passwords.last(), "password wiped on close")
    }

    @Test
    fun wrongPassword() {
        val creator = newViewModel()
        creator.create("backup")
        assertTrue(runBlocking { creator.save(account("A")).await() })
        platform.otpStorage = MemoryStorageProvider()
        val vm = newViewModel()
        vm.open(config)
        vm.unlock("wrong")
        val locked = vm.await { it is OtpState.Locked && it.error != null } as OtpState.Locked
        assertEquals("Wrong password.", locked.error)
        assertTrue(passwords.last().all { it == 0.toByte() })
    }

    @Test
    fun offlineLocalCopy() {
        val vm = newViewModel()
        vm.create("backup")
        assertTrue(runBlocking { vm.save(account("A")).await() })
        vm.lock()
        server.close()
        vm.unlock("backup")
        val offline = vm.await<OtpState.Unlocked>()
        assertEquals(ClientValue.LocalReason.SERVER_UNAVAILABLE, offline.localReason)
        assertEquals("Server unavailable, loaded local copy", offline.status?.text)
        assertEquals(listOf("A"), offline.accounts.map { it.issuer })
    }

    @Test
    fun idleLock() {
        val vm = newViewModel(idleLockTimeoutMs = 500)
        vm.create("backup")
        // activity keeps it unlocked
        repeat(15) {
            vm.onActivity()
            Thread.sleep(50)
        }
        assertTrue(vm.state.value is OtpState.Unlocked)
        vm.await<OtpState.Locked>()
        assertWipedSoon(passwords.last(), "password wiped on idle lock")
    }

    @Test
    fun backgroundLocksRightAway() {
        val vm = newViewModel()
        vm.create("backup")
        vm.onBackground()
        assertTrue(vm.state.value is OtpState.Locked)
        vm.onForeground()
        assertTrue(vm.state.value is OtpState.Locked)
    }

    /**
     * An unsaved draft survives a short trip to another app (e.g. to copy the secret), but not a long one.
     */
    @Test
    fun backgroundKeepsDraftsForAWhile() {
        val vm = newViewModel(backgroundDraftTimeoutMs = 300)
        vm.create("backup")
        vm.screenState.startEditing(null)
        vm.screenState.draft = vm.screenState.draft.copy(issuer = "GitHub")
        vm.onBackground()
        vm.onForeground()
        assertTrue(vm.state.value is OtpState.Unlocked)
        assertEquals("GitHub", vm.screenState.draft.issuer)

        vm.onBackground()
        vm.await<OtpState.Locked>()
        assertEquals("", vm.screenState.draft.issuer, "drafts are gone with the session")
    }

    /** A vault with one account on the server, created with the password "backup" */
    private fun existingVault() {
        val creator = newViewModel()
        creator.create("backup")
        assertTrue(runBlocking { creator.save(account("A")).await() })
        creator.close()
    }

    private fun fingerprintViewModel(keyStore: FakeOtpKeyStore, authenticator: FakeAuthenticator): OtpViewModel {
        platform.otpKeyStore = keyStore
        return newViewModel().also { it.authenticator = authenticator }
    }

    @Test
    fun fingerprint() {
        existingVault()
        val keyStore = FakeOtpKeyStore()
        val authenticator = FakeAuthenticator()
        val vm = fingerprintViewModel(keyStore, authenticator)

        // without a key, opening asks for the password, which offers the fingerprint
        vm.open(config)
        assertEquals(false, vm.await<OtpState.Locked>().fingerprint)
        vm.unlock("backup")
        assertTrue(vm.await<OtpState.Unlocked>().offerFingerprint)
        vm.enableFingerprint()
        val enabled = vm.awaitIdle()
        assertEquals("Fingerprint unlock enabled", enabled.status?.text)
        assertEquals(false, enabled.offerFingerprint)
        assertNotNull(keyStore.key)

        // opening again takes nothing but the fingerprint, and the vault can be changed
        vm.close()
        vm.open(config)
        val unlocked = vm.await<OtpState.Unlocked>()
        assertEquals(listOf("A"), unlocked.accounts.map { it.issuer })
        assertEquals(false, unlocked.offerFingerprint)
        assertTrue(runBlocking { vm.save(account("B")).await() })

        // the change reached the server
        platform.otpKeyStore = null
        platform.otpStorage = MemoryStorageProvider()
        val other = newViewModel()
        other.open(config)
        other.unlock("backup")
        assertEquals(listOf("A", "B"), other.await<OtpState.Unlocked>().accounts.map { it.issuer })
    }

    /**
     * Back from the background, a vault that was locked there opens with the fingerprint right away.
     */
    @Test
    fun fingerprintAfterBackground() {
        existingVault()
        val keyStore = FakeOtpKeyStore()
        val authenticator = FakeAuthenticator()
        val vm = fingerprintViewModel(keyStore, authenticator)
        vm.open(config)
        vm.unlock("backup")
        vm.await<OtpState.Unlocked>()
        vm.enableFingerprint()
        vm.awaitIdle()
        vm.onBackground()
        assertTrue(vm.state.value is OtpState.Locked)
        vm.onForeground()
        vm.await<OtpState.Unlocked>()
        assertEquals(2, authenticator.count)
        // a vault that was locked anyway stays so
        vm.lock()
        vm.onBackground()
        vm.onForeground()
        assertTrue(vm.state.value is OtpState.Locked)
        assertEquals(2, authenticator.count)
    }

    @Test
    fun fingerprintCancelled() {
        existingVault()
        val keyStore = FakeOtpKeyStore()
        val authenticator = FakeAuthenticator()
        val vm = fingerprintViewModel(keyStore, authenticator)
        vm.open(config)
        vm.unlock("backup")
        vm.await<OtpState.Unlocked>()
        vm.enableFingerprint()
        vm.awaitIdle()
        vm.close()

        authenticator.cancel = true
        vm.open(config)
        val locked = vm.await { it is OtpState.Locked && authenticator.count == 2 } as OtpState.Locked
        assertNull(locked.error)
        assertTrue(locked.fingerprint, "the key is kept")
        authenticator.cancel = false
        vm.unlockWithFingerprint()
        vm.await<OtpState.Unlocked>()
    }

    @Test
    fun fingerprintInvalidated() {
        existingVault()
        val keyStore = FakeOtpKeyStore().apply { key = ByteArray(64); url = config.url; invalidated = true }
        val vm = fingerprintViewModel(keyStore, FakeAuthenticator())
        vm.open(config)
        val locked = vm.await { it is OtpState.Locked && it.error != null } as OtpState.Locked
        assertTrue(locked.error!!.contains("no longer valid"))
        assertEquals(false, locked.fingerprint)
        assertNull(keyStore.key, "deleted")
    }

    /**
     * The key of another vault, e.g. after the vault was reset and created again, is deleted.
     */
    @Test
    fun fingerprintOfAnotherVault() {
        existingVault()
        val keyStore = FakeOtpKeyStore().apply { key = ByteArray(64) { 1 }; url = config.url }
        val vm = fingerprintViewModel(keyStore, FakeAuthenticator())
        vm.open(config)
        val locked = vm.await { it is OtpState.Locked && it.error != null } as OtpState.Locked
        assertTrue(locked.error!!.contains("created again"), locked.error)
        assertNull(keyStore.key, "deleted")
    }

    /**
     * A new vault is only on the server after its first save, and only then has a key to keep.
     */
    @Test
    fun fingerprintOfferedAfterFirstSave() {
        val vm = fingerprintViewModel(FakeOtpKeyStore(), FakeAuthenticator())
        vm.create("backup")
        assertEquals(false, (vm.state.value as OtpState.Unlocked).offerFingerprint)
        assertTrue(runBlocking { vm.save(account("A")).await() })
        assertTrue(vm.awaitIdle().offerFingerprint)
        vm.dismissFingerprintOffer()
        assertEquals(false, (vm.state.value as OtpState.Unlocked).offerFingerprint)
        assertTrue(runBlocking { vm.save(account("B")).await() })
        assertEquals(false, vm.awaitIdle().offerFingerprint, "not again in this session")
    }

    /**
     * A key is only used for its own server: with another URL it would sign requests for a server that doesn't have
     * its vault, and could be deleted because that server has another one.
     */
    @Test
    fun fingerprintOfAnotherServer() {
        existingVault()
        val keyStore = FakeOtpKeyStore().apply { key = ByteArray(64) { 1 }; url = "https://other.example.com" }
        val authenticator = FakeAuthenticator()
        val vm = fingerprintViewModel(keyStore, authenticator)
        vm.open(config)
        val locked = vm.await<OtpState.Locked>()
        assertEquals(false, locked.fingerprint)
        vm.unlockWithFingerprint()
        assertEquals(0, authenticator.count, "never prompted")
        assertNotNull(keyStore.key, "kept")

        // unlocking with the password offers a key for this server, which replaces the other one
        vm.unlock("backup")
        assertTrue(vm.await<OtpState.Unlocked>().offerFingerprint)
        vm.enableFingerprint()
        vm.awaitIdle()
        assertEquals(config.url, keyStore.url)
    }

    @Test
    fun savesUrlThatWorked() {
        existingVault()
        platform.savedUrls.clear()
        val vm = newViewModel()
        vm.open(config)
        vm.unlock("backup")
        vm.await<OtpState.Unlocked>()
        // the fake platform's configuration has the same URL: nothing to save
        assertTrue(platform.savedUrls.isEmpty())

        platform.config = platform.config.copy(url = "https://old.example.com")
        vm.lock()
        vm.unlock("backup")
        vm.await<OtpState.Unlocked>()
        assertEquals(listOf(server.url), platform.savedUrls)
    }

    /**
     * Resetting the vault on the server locks out the fingerprint (e.g. of a lost phone): the key is deleted, although
     * it still opens the local copy.
     */
    @Test
    fun fingerprintAfterReset() {
        existingVault()
        val keyStore = FakeOtpKeyStore()
        val vm = fingerprintViewModel(keyStore, FakeAuthenticator())
        vm.open(config)
        vm.unlock("backup")
        vm.await<OtpState.Unlocked>()
        vm.enableFingerprint()
        vm.awaitIdle()
        vm.close()

        server.totpRegistration.set(null)
        server.totpDb.set(null)
        vm.open(config)
        val locked = vm.await { it is OtpState.Locked && it.error != null } as OtpState.Locked
        assertTrue(locked.error!!.contains("reset"), locked.error)
        assertNull(keyStore.key, "deleted")
        assertEquals(false, locked.fingerprint)
    }

    @Test
    fun noOfferWithoutBiometrics() {
        existingVault()
        val vm = fingerprintViewModel(FakeOtpKeyStore().apply { canStore = false }, FakeAuthenticator())
        vm.open(config)
        vm.unlock("backup")
        assertEquals(false, vm.await<OtpState.Unlocked>().offerFingerprint)
    }

    /**
     * "Not now" lasts beyond locking (which on Android happens with every switch to another app).
     */
    @Test
    fun dismissedOfferStaysDismissed() {
        existingVault()
        val vm = fingerprintViewModel(FakeOtpKeyStore(), FakeAuthenticator())
        vm.open(config)
        vm.unlock("backup")
        assertTrue(vm.await<OtpState.Unlocked>().offerFingerprint)
        vm.dismissFingerprintOffer()
        vm.lock()
        vm.unlock("backup")
        assertEquals(false, vm.await<OtpState.Unlocked>().offerFingerprint)
    }

    /**
     * A key for this server, but of another vault (created again since), doesn't keep the offer away.
     */
    @Test
    fun offerReplacesKeyOfOldVault() {
        existingVault()
        val keyStore = FakeOtpKeyStore().apply { key = ByteArray(64) { 9 }; url = config.url }
        val authenticator = FakeAuthenticator().apply { cancel = true }
        val vm = fingerprintViewModel(keyStore, authenticator)
        vm.open(config)
        vm.await { it is OtpState.Locked && authenticator.count == 1 }
        authenticator.cancel = false
        vm.unlock("backup")
        assertTrue(vm.await<OtpState.Unlocked>().offerFingerprint)
    }

    @Test
    fun forgetFingerprint() {
        existingVault()
        val keyStore = FakeOtpKeyStore()
        val authenticator = FakeAuthenticator().apply { cancel = true }
        keyStore.key = ByteArray(64)
        keyStore.url = config.url
        val vm = fingerprintViewModel(keyStore, authenticator)
        vm.open(config)
        assertTrue(vm.await { it is OtpState.Locked && authenticator.count == 1 }.let { (it as OtpState.Locked).fingerprint })
        vm.forgetFingerprint()
        assertEquals(false, (vm.state.value as OtpState.Locked).fingerprint)
        assertNull(keyStore.key)
    }

    @Test
    fun lockNowWhileClosedDoesNothing() {
        val vm = newViewModel()
        vm.lockNow()
        assertEquals(OtpState.Closed, vm.state.value)
        vm.open(config)
        vm.lockNow()
        assertTrue(vm.state.value is OtpState.Locked)
    }

    @Test
    fun importFile() {
        val vm = newViewModel()
        platform.textFile = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"
        assertTrue(vm.canPickTextFile)
        assertEquals(platform.textFile, runBlocking { vm.pickImportFile() })
    }
}
