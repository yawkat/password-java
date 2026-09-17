package at.yawk.password.gui;

import at.yawk.password.HashUtil;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.MemoryStorageProvider;
import at.yawk.password.client.PasswordClient;
import at.yawk.password.model.PasswordEntry;
import at.yawk.password.server.DatabaseServer;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import spark.Spark;

/**
 * @author yawkat
 */
public class PasswordStoreTest {
    private static final int PORT = 1235;
    private static final String URL = "http://127.0.0.1:" + PORT;

    @BeforeClass
    public void open() {
        Spark.port(PORT);
        new DatabaseServer(new MemoryStorageProvider(), new MemoryStorageProvider()).start();
        Spark.awaitInitialization();
    }

    @AfterClass
    public void close() {
        Spark.stop();
        Spark.awaitStop();
    }

    @Test
    public void testModifyAndReload() throws Exception {
        byte[] password = HashUtil.generateRandomBytes(16);
        LocalStorageProvider storage = new MemoryStorageProvider();
        PasswordClient client = new PasswordClient(URL, storage, password);

        Assert.assertNull(PasswordStore.open(client));
        PasswordStore store = PasswordStore.createEmpty(client);

        PasswordEntry a = store.add("a", "pw-a\nuser");
        PasswordEntry b = store.add("b", "pw-b");
        PasswordEntry a2 = store.update(a, "a2", "pw-a2");
        store.delete(b);
        Assert.assertEquals(store.getEntries().size(), 1);
        Assert.assertSame(store.getEntries().get(0), a2);

        PasswordStore reopened = PasswordStore.open(new PasswordClient(URL, new MemoryStorageProvider(), password));
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
        // nothing listens on port 1, so saving to the remote fails
        PasswordStore store = PasswordStore.createEmpty(
                new PasswordClient("http://127.0.0.1:1", new MemoryStorageProvider(), password));
        Assert.assertThrows(() -> store.add("a", "b"));
        Assert.assertTrue(store.getEntries().isEmpty());
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
