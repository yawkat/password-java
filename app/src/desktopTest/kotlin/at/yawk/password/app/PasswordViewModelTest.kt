package at.yawk.password.app

import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import at.yawk.password.LocalStorageProvider
import at.yawk.password.MemoryStorageProvider
import at.yawk.password.client.PasswordClient
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

class PasswordViewModelTest {
    private lateinit var server: FakeServer
    private lateinit var storage: MemoryStorageProvider
    private lateinit var platform: FakePlatform
    private val stores = mutableListOf<ViewModelStore>()

    /** Every password array handed to a client, to check that they get wiped */
    private val passwords = mutableListOf<ByteArray>()

    @BeforeTest
    fun setUp() {
        server = FakeServer()
        storage = MemoryStorageProvider()
        platform = FakePlatform(AppConfig(server.url, "/nonexistent"), storage)
    }

    @AfterTest
    fun tearDown() {
        stores.forEach { it.clear() }
        stores.clear()
        server.close()
    }

    private fun newViewModel(): PasswordViewModel {
        val store = ViewModelStore().also { stores += it }
        val factory = viewModelFactory {
            initializer {
                PasswordViewModel(platform, clientFactory = { url, storage, password ->
                    passwords += password
                    PasswordClient(url, storage, password)
                })
            }
        }
        return ViewModelProvider.create(store, factory)[PasswordViewModel::class]
    }

    private fun PasswordViewModel.await(predicate: (UiState) -> Boolean): UiState = runBlocking {
        withTimeout(120_000) { state.first(predicate) }
    }

    private inline fun <reified T : UiState> PasswordViewModel.await(): T = await { it is T } as T

    private fun PasswordViewModel.awaitIdle(): UiState.Unlocked = await { it is UiState.Unlocked && !it.busy } as UiState.Unlocked

    @Test
    fun createEditAndReopen() {
        val vm = newViewModel()
        assertEquals(server.url, vm.await<UiState.Locked>().config.url)

        // empty password is ignored
        vm.unlock(server.url, "")
        assertTrue(vm.state.value is UiState.Locked)

        // no database: offer to create one, but only with the same password
        vm.unlock(server.url, "secret")
        vm.await<UiState.ConfirmCreate>()
        vm.confirmCreate("other")
        assertEquals("The passwords do not match.", vm.await<UiState.Locked>().error)
        assertTrue(passwords.last().all { it == 0.toByte() }, "password wiped after mismatch")

        vm.unlock(server.url, "secret")
        vm.await<UiState.ConfirmCreate>()
        vm.confirmCreate("secret")
        val empty = vm.await<UiState.Unlocked>()
        assertTrue(empty.entries.isEmpty())
        assertFalse(empty.fromLocalStorage)
        assertNull(server.db.get(), "nothing saved before the first modification")

        val a = runBlocking { vm.save(null, "a", "pw-a\nuser").await() }
        assertNotNull(a)
        val b = runBlocking { vm.save(null, "b", "pw-b").await() }
        assertNotNull(b)
        val a2 = runBlocking { vm.save(a, "a2", "pw-a2").await() }
        assertNotNull(a2)
        assertTrue(runBlocking { vm.delete(b).await() })
        val afterEdits = vm.awaitIdle()
        assertEquals(listOf("a2"), afterEdits.entries.map { it.name })
        assertEquals("Deleted “b”", afterEdits.status?.text)
        assertNotNull(server.db.get())
        assertNotNull(storage.load(), "local copy written")

        assertTrue(runBlocking { vm.reload().await() })
        assertEquals("Reloaded 1 entries", vm.awaitIdle().status?.text)

        val sessionPassword = passwords.last()
        vm.lock()
        vm.await<UiState.Locked>()
        assertTrue(sessionPassword.all { it == 0.toByte() }, "password wiped on lock")

        // a fresh app with a fresh local copy sees the same data from the server
        platform.storage = MemoryStorageProvider()
        val reopened = newViewModel()
        reopened.await<UiState.Locked>()
        reopened.unlock(server.url, "secret")
        val loaded = reopened.await<UiState.Unlocked>()
        assertEquals(listOf("a2"), loaded.entries.map { it.name })
        assertEquals("pw-a2", loaded.entries.single().value)
        assertFalse(loaded.fromLocalStorage)
        assertEquals("1 entries loaded", loaded.status?.text)
    }

    @Test
    fun wrongPassword() {
        createDatabase("secret")
        val vm = newViewModel()
        vm.await<UiState.Locked>()
        vm.unlock(server.url, "wrong")
        assertTrue(vm.state.value is UiState.Unlocking)
        assertEquals("Wrong password.", vm.await<UiState.Locked>().error)
        assertTrue(passwords.last().all { it == 0.toByte() }, "password wiped after failed unlock")
    }

    @Test
    fun cancelCreate() {
        val vm = newViewModel()
        vm.await<UiState.Locked>()
        vm.unlock(server.url, "secret")
        vm.await<UiState.ConfirmCreate>()
        vm.cancelCreate()
        assertNull(vm.await<UiState.Locked>().error)
        assertTrue(passwords.last().all { it == 0.toByte() })
    }

    @Test
    fun offlineCopy() {
        createDatabase("secret", "entry" to "pw")
        val url = server.url
        server.close()

        val vm = newViewModel()
        vm.await<UiState.Locked>()
        vm.unlock(url, "secret")
        val offline = vm.await<UiState.Unlocked>()
        assertTrue(offline.fromLocalStorage)
        assertEquals(listOf("entry"), offline.entries.map { it.name })
        assertFalse(offline.offlineSaveConfirmed)
        vm.confirmOfflineSave()
        assertTrue((vm.state.value as UiState.Unlocked).offlineSaveConfirmed)

        // saving fails because the server is down, and the state is kept
        assertNull(runBlocking { vm.save(null, "new", "value").await() })
        val failed = vm.awaitIdle()
        assertEquals("Save failed", failed.error?.title)
        assertEquals(listOf("entry"), failed.entries.map { it.name })
        vm.dismissError()
        assertNull((vm.state.value as UiState.Unlocked).error)

        // reload falls back to the local copy again and resets the confirmation
        assertTrue(runBlocking { vm.reload().await() })
        val reloaded = vm.awaitIdle()
        assertEquals("Server unreachable, loaded local copy", reloaded.status?.text)
        assertFalse(reloaded.offlineSaveConfirmed)
    }

    @Test
    fun modificationsAreSerialized() {
        val vm = newViewModel()
        vm.await<UiState.Locked>()
        vm.unlock(server.url, "secret")
        vm.await<UiState.ConfirmCreate>()
        vm.confirmCreate("secret")
        vm.await<UiState.Unlocked>()

        val first = vm.save(null, "a", "1")
        assertTrue((vm.state.value as UiState.Unlocked).busy)
        assertEquals("Saving…", (vm.state.value as UiState.Unlocked).status?.text)
        // refused while the first save runs
        val second = vm.save(null, "b", "2")
        assertNull(runBlocking { second.await() })
        assertNotNull(runBlocking { first.await() })
        assertEquals(listOf("a"), vm.awaitIdle().entries.map { it.name })
    }

    @Test
    fun changedUrlIsSaved() {
        val vm = newViewModel()
        vm.await<UiState.Locked>()
        platform.config = platform.config.copy(url = "http://127.0.0.1:1")
        // the view model still has the old config; entering the real URL saves it
        val vm2 = newViewModel()
        assertEquals("http://127.0.0.1:1", vm2.await<UiState.Locked>().config.url)
        vm2.unlock(" ${server.url} ", "secret")
        assertEquals(server.url, vm2.await<UiState.ConfirmCreate>().config.url)
        assertEquals(listOf(server.url), platform.savedUrls)
    }

    @Test
    fun reloadedEntriesReachTheState() {
        val vm = newViewModel()
        vm.await<UiState.Locked>()
        vm.unlock(server.url, "secret")
        vm.await<UiState.ConfirmCreate>()
        vm.confirmCreate("secret")
        vm.await<UiState.Unlocked>()
        val a = runBlocking { vm.save(null, "a", "1").await() }!!

        // the reload returns equal entries, but new objects; only those are accepted by the store
        assertTrue(runBlocking { vm.reload().await() })
        val reloaded = vm.awaitIdle().entries.single()
        assertEquals(a, reloaded)
        assertTrue(a !== reloaded)
        assertNotNull(runBlocking { vm.save(reloaded, "a", "2").await() })
        assertNull(vm.awaitIdle().error)
    }

    @Test
    fun urlIsNotSavedWhenUnlockFails() {
        val vm = newViewModel()
        vm.await<UiState.Locked>()
        // nothing listens on port 1 and there is no local copy
        vm.unlock("http://127.0.0.1:1", "secret")
        assertTrue(vm.await<UiState.Locked>().error!!.startsWith("Could not load the database"))
        assertEquals(listOf(), platform.savedUrls)
    }

    @Test
    fun urlSaveFailureDoesNotFailUnlock() {
        createDatabase("secret", "entry" to "pw")
        platform.config = platform.config.copy(url = "http://127.0.0.1:1")
        platform.saveError = java.io.IOException("read-only")
        val vm = newViewModel()
        vm.await<UiState.Locked>()
        vm.unlock(server.url, "secret")
        val unlocked = vm.await<UiState.Unlocked>()
        assertEquals(listOf("entry"), unlocked.entries.map { it.name })
        assertEquals("Could not save the server URL: read-only", unlocked.status?.text)
    }

    @Test
    fun configError() {
        platform.configError = IllegalStateException("broken")
        val vm = newViewModel()
        assertTrue(vm.await<UiState.Error>().message.contains("broken"))
    }

    private fun createDatabase(password: String, vararg entries: Pair<String, String>) {
        val vm = newViewModel()
        vm.await<UiState.Locked>()
        vm.unlock(server.url, password)
        vm.await<UiState.ConfirmCreate>()
        vm.confirmCreate(password)
        vm.await<UiState.Unlocked>()
        for ((name, value) in entries) {
            assertNotNull(runBlocking { vm.save(null, name, value).await() })
        }
        if (entries.isEmpty()) {
            // force a save so the database exists
            val entry = runBlocking { vm.save(null, "x", "y").await() }
            assertTrue(runBlocking { vm.delete(entry!!).await() })
        }
    }

    private class FakePlatform(var config: AppConfig, var storage: LocalStorageProvider) : Platform {
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
    }
}

class SecretsTest {
    @Test
    fun encodePasswordMatchesString() {
        for (s in listOf("", "abc", "äöü€", "🔑", "broken \uD800 surrogate")) {
            assertContentEquals(s.toByteArray(Charsets.UTF_8), encodePassword(StringBuilder(s)))
        }
    }

    @Test
    fun maskAndGenerate() {
        assertEquals(PASSWORD_MASK, maskedValue(null))
        assertEquals("$PASSWORD_MASK\nuser", maskedValue("pw\nuser"))
        val generated = withGeneratedPassword("old\nuser")
        assertTrue(generated.endsWith("\nuser"))
        assertEquals(24, generated.indexOf('\n'))
        assertTrue(generated.substring(0, 24).all { it in 'a'..'z' || it in '0'..'9' })
    }

    @Test
    fun filter() {
        val entries = listOf("beta", "Alpha", "gamma", "alphabet").map {
            at.yawk.password.model.PasswordEntry().apply { name = it }
        }
        assertEquals(listOf("Alpha", "alphabet", "beta", "gamma"), filterEntries(entries, "").map { it.name })
        assertEquals(listOf("Alpha", "alphabet"), filterEntries(entries, "ALPH").map { it.name })
    }
}
