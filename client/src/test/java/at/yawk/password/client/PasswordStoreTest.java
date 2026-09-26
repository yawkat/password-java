package at.yawk.password.client;

import at.yawk.password.HashUtil;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.MemoryStorageProvider;
import at.yawk.password.model.PasswordEntry;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicReference;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class PasswordStoreTest {
    private HttpServer server;
    private String url;

    /**
     * Minimal in-memory stand-in for the server that stores {@code /db} without checking tokens. Spark only supports
     * a single server per JVM, which {@code ClientServerTest} already uses.
     */
    @BeforeClass
    public void open() throws Exception {
        AtomicReference<byte[]> db = new AtomicReference<>();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body;
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/challenge")) {
                body = HashUtil.generateRandomBytes(32);
            } else if (path.equals("/db") && exchange.getRequestMethod().equals("PUT")) {
                db.set(exchange.getRequestBody().readAllBytes());
                body = new byte[0];
            } else if (path.equals("/db")) {
                body = db.get();
            } else {
                body = null;
            }
            if (body == null) {
                exchange.sendResponseHeaders(404, -1);
            } else {
                exchange.sendResponseHeaders(200, body.length == 0 ? -1 : body.length);
                exchange.getResponseBody().write(body);
            }
            exchange.close();
        });
        server.start();
        url = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterClass
    public void close() {
        server.stop(0);
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
