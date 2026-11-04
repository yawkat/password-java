package at.yawk.password.client;

import at.yawk.password.HashUtil;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.MemoryStorageProvider;
import at.yawk.password.model.Passkey;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.model.PasswordEntry;
import at.yawk.password.passkey.PasskeyAuthenticator;
import at.yawk.password.server.TestServer;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.List;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class PasswordStoreTest {
    private TestServer server;
    private String url;

    @BeforeClass
    public void open() throws Exception {
        server = TestServer.start();
        url = server.getUrl();
    }

    @AfterClass
    public void close() {
        server.close();
    }

    @Test
    public void testModifyAndReload() throws Exception {
        byte[] password = HashUtil.generateRandomBytes(16);
        LocalStorageProvider storage = new MemoryStorageProvider();
        PasswordClient client = new PasswordClient(url, storage, password);

        Assert.assertNull(PasswordStore.open(client));
        PasswordStore store = PasswordStore.createEmpty(client);

        PasswordEntry a = store.add("a", "pw-a\nuser");
        PasswordEntry b = store.add("b", "pw-b");
        PasswordEntry a2 = store.update(a, "a2", "pw-a2");
        store.delete(b);
        Assert.assertEquals(store.getEntries().size(), 1);
        Assert.assertSame(store.getEntries().get(0), a2);

        PasswordStore reopened = PasswordStore.open(new PasswordClient(url, new MemoryStorageProvider(), password));
        Assert.assertNotNull(reopened);
        Assert.assertFalse(reopened.isFromLocalStorage());
        Assert.assertEquals(reopened.getEntries(), store.getEntries());

        store.reload();
        Assert.assertEquals(store.getEntries().size(), 1);
        Assert.assertEquals(store.getEntries().get(0).getName(), "a2");
    }

    @Test
    public void testFailedSaveKeepsState() throws Exception {
        byte[] password = HashUtil.generateRandomBytes(16);
        PasswordStore store;
        try (TestServer stopped = TestServer.start()) {
            PasswordClient client = new PasswordClient(stopped.getUrl(), new MemoryStorageProvider(), password);
            Assert.assertNull(PasswordStore.open(client));
            store = PasswordStore.createEmpty(client);
        }
        // the server is gone, so saving to the remote fails
        Assert.assertThrows(IOException.class, () -> store.add("a", "b"));
        Assert.assertTrue(store.getEntries().isEmpty());
    }

    @Test
    public void testSaveBeforeLoad() {
        PasswordStore store = PasswordStore.createEmpty(
                new PasswordClient(url, new MemoryStorageProvider(), HashUtil.generateRandomBytes(16)));
        Assert.assertThrows(IllegalStateException.class, () -> store.add("a", "b"));
    }

    @Test
    public void testPasskeys() throws Exception {
        // a server of its own: the shared one is registered with the password of another test
        try (TestServer server = TestServer.start()) {
            String url = server.getUrl();
            byte[] password = HashUtil.generateRandomBytes(16);
            PasswordClient client = new PasswordClient(url, new MemoryStorageProvider(), password);
            Assert.assertNull(PasswordStore.open(client));
            PasswordStore store = PasswordStore.createEmpty(client);
            Passkey a = PasskeyAuthenticator.create("example.com", new byte[]{1}, "alice", "", 0);
            Passkey b = PasskeyAuthenticator.create("example.org", new byte[]{1}, "alice", "", 0);
            store.addPasskey(a);
            store.addPasskey(b);
            // password edits keep the passkeys
            PasswordEntry entry = store.add("a", "b");
            store.update(entry, "a", "c");
            Assert.assertEquals(store.getPasskeys(), List.of(a, b));

            // the same account at the same relying party replaces the old passkey
            Passkey a2 = PasskeyAuthenticator.create("example.com", new byte[]{1}, "alice2", "", 0);
            store.addPasskey(a2);
            Assert.assertEquals(store.getPasskeys(), List.of(b, a2));

            PasswordStore reopened = PasswordStore.open(
                    new PasswordClient(url, new MemoryStorageProvider(), password));
            Assert.assertNotNull(reopened);
            Assert.assertEquals(reopened.getPasskeys(), List.of(b, a2));
            Assert.assertEquals(reopened.getEntries().size(), 1);

            store.deletePasskey(b);
            Assert.assertEquals(store.getPasskeys(), List.of(a2));
            Assert.assertEquals(store.getEntries().size(), 1);
        }
    }

    @Test
    public void testPasskeysJson() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        // left out while empty, so that clients that predate passkeys keep opening the database
        Assert.assertEquals(mapper.writeValueAsString(new PasswordBlob()), "{\"passwords\":[]}");
        PasswordBlob read = mapper.readValue("{\"passwords\":[]}", PasswordBlob.class);
        Assert.assertEquals(read.getPasskeys(), List.of());

        read = mapper.readValue(
                "{\"passwords\":[],\"passkeys\":[null,{\"id\":\"x\",\"rpId\":\"a\"},{\"id\":\"x\"}," +
                "{\"id\":null,\"userName\":null}]}",
                PasswordBlob.class);
        Assert.assertEquals(read.getPasskeys().size(), 3);
        Assert.assertEquals(read.getPasskeys().get(0).getId(), "x");
        Assert.assertEquals(read.getPasskeys().get(0).getRpId(), "a");
        // duplicate and missing ids get new ones
        Assert.assertNotEquals(read.getPasskeys().get(1).getId(), "x");
        Assert.assertNotNull(read.getPasskeys().get(2).getId());
        Assert.assertEquals(read.getPasskeys().get(2).getUserName(), "");

        Passkey passkey = PasskeyAuthenticator.create("example.com", new byte[]{1}, "alice", "Alice", 5);
        PasswordBlob blob = new PasswordBlob();
        blob.setPasskeys(List.of(passkey));
        String json = mapper.writeValueAsString(blob);
        Assert.assertEquals(mapper.readValue(json, PasswordBlob.class), blob);
        Assert.assertEquals(
                mapper.readTree(json).path("passkeys").path(0).properties().stream().map(e -> e.getKey()).toList(),
                List.of("id", "rpId", "credentialId", "userHandle", "userName", "userDisplayName", "privateKey",
                        "created"));
    }

    @Test
    public void testFirstLine() {
        Assert.assertEquals(PasswordStore.firstLine(null), "");
        Assert.assertEquals(PasswordStore.firstLine(""), "");
        Assert.assertEquals(PasswordStore.firstLine("single"), "single");
        Assert.assertEquals(PasswordStore.firstLine("pw\nuser"), "pw");
        Assert.assertEquals(PasswordStore.firstLine("pw\r\nuser"), "pw");
        Assert.assertEquals(PasswordStore.firstLine("\nuser"), "");
    }
}
