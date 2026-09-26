package at.yawk.password.client;

import at.yawk.password.MemoryStorageProvider;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.model.PasswordEntry;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import tools.jackson.databind.ObjectMapper;

/**
 * Regression tests for #9: a remote database that fails verification must not replace the local copy.
 *
 * @author yawkat
 */
public class VerifyBeforeSaveTest {
    private static final byte[] PASSWORD = { 1, 2, 3 };

    private static PasswordBlob blob(String name) {
        PasswordEntry entry = new PasswordEntry();
        entry.setName(name);
        entry.setValue("value");
        PasswordBlob blob = new PasswordBlob();
        blob.getPasswords().add(entry);
        return blob;
    }

    private static byte[] encrypt(byte[] password, PasswordBlob blob) throws Exception {
        DecryptedBlob decrypted = new DecryptedBlob();
        decrypted.setData(blob);
        return AesCodec.encrypt(new ObjectMapper(), password, decrypted).write();
    }

    @DataProvider
    public Object[][] badRemotes() throws Exception {
        return new Object[][]{
                { "garbage".getBytes() },
                { encrypt("other password".getBytes(), blob("remote")) },
        };
    }

    /**
     * Minimal stand-in for the server that serves {@code remoteDb} on {@code GET /db}.
     */
    private static class Server implements AutoCloseable {
        final AtomicInteger dbRequests = new AtomicInteger();
        final HttpServer server;

        Server(byte[] remoteDb) throws Exception {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                byte[] body;
                if (exchange.getRequestURI().getPath().equals("/db")) {
                    dbRequests.incrementAndGet();
                    body = remoteDb;
                } else {
                    body = new byte[]{ 4, 5, 6 };
                }
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
            });
            server.start();
        }

        PasswordClient client(MemoryStorageProvider storage) {
            return new PasswordClient("http://127.0.0.1:" + server.getAddress().getPort(), storage, PASSWORD);
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    @Test(dataProvider = "badRemotes")
    public void testUnverifiedRemoteFallsBackToLocal(byte[] remoteDb) throws Exception {
        PasswordBlob localBlob = blob("local");
        byte[] localDb = encrypt(PASSWORD, localBlob);
        MemoryStorageProvider storage = new MemoryStorageProvider();
        storage.save(localDb);

        try (Server server = new Server(remoteDb)) {
            ClientValue<PasswordBlob> loaded = server.client(storage).load();
            Assert.assertEquals(server.dbRequests.get(), 1);
            Assert.assertTrue(loaded.isFromLocalStorage());
            Assert.assertEquals(loaded.getValue(), localBlob);
            Assert.assertSame(storage.load(), localDb);
        }
    }

    @Test
    public void testUnverifiedRemoteWithoutLocalCopy() throws Exception {
        MemoryStorageProvider storage = new MemoryStorageProvider();

        try (Server server = new Server(encrypt("other password".getBytes(), blob("remote")))) {
            Exception e = Assert.expectThrows(Exception.class, server.client(storage)::load);
            Assert.assertTrue(e.getMessage().startsWith("Invalid HMAC"), e.getMessage());
            Assert.assertEquals(server.dbRequests.get(), 1);
            Assert.assertNull(storage.load());
        }
    }

    @Test
    public void testVerifiedRemoteIsSaved() throws Exception {
        MemoryStorageProvider storage = new MemoryStorageProvider();
        storage.save(encrypt(PASSWORD, blob("local")));
        PasswordBlob remoteBlob = blob("remote");
        byte[] remoteDb = encrypt(PASSWORD, remoteBlob);

        try (Server server = new Server(remoteDb)) {
            ClientValue<PasswordBlob> loaded = server.client(storage).load();
            Assert.assertFalse(loaded.isFromLocalStorage());
            Assert.assertEquals(loaded.getValue(), remoteBlob);
            Assert.assertEquals(storage.load(), remoteDb);
        }
    }
}
