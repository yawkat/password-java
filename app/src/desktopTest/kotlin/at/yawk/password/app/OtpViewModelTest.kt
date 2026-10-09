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

    private fun newViewModel(idleLockTimeoutMs: Long = OTP_IDLE_LOCK_TIMEOUT_MS): OtpViewModel {
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
        assertTrue(sessionPassword.all { it == 0.toByte() }, "password wiped on lock")

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
        assertTrue(passwords.last().all { it == 0.toByte() }, "password wiped on close")
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
        assertTrue(passwords.last().all { it == 0.toByte() }, "password wiped on idle lock")
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
