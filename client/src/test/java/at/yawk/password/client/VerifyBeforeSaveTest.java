package at.yawk.password.client;

import at.yawk.password.AuthProtocol;
import at.yawk.password.HashUtil;
import at.yawk.password.MemoryStorageProvider;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.PasswordBlob;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Regression tests for #9: a remote database that fails verification must not replace the local copy. Also the
 * rollback check: a remote database older than the local copy must not replace it either.
 *
 * @author yawkat
 */
public class VerifyBeforeSaveTest {
    private static final byte[] PASSWORD = { 1, 2, 3 };
    private static final byte[] SALT = HashUtil.generateRandomBytes(AuthProtocol.SALT_LENGTH);
    private static final KeyMaterial KEYS = KeyMaterial.derive(PASSWORD, SALT);
    private static final KeyMaterial OTHER_PASSWORD_KEYS = KeyMaterial.derive("other password".getBytes(), SALT);

    private static byte[] encrypt(KeyMaterial keys, long revision, String name) throws Exception {
        return BlobCodec.encrypt(new ObjectMapper(), keys, BlobCodecTest.blob(revision, name, "value"));
    }

    private static PasswordBlob data(String name) {
        return BlobCodecTest.blob(0, name, "value").getData();
    }

    @DataProvider
    public Object[][] badRemotes() throws Exception {
        return new Object[][]{
                { "garbage".getBytes() },
                { encrypt(OTHER_PASSWORD_KEYS, 5, "remote") },
                // older than the local copy
                { encrypt(KEYS, 1, "remote") },
        };
    }

    /**
     * Minimal stand-in for the server that serves {@code remoteDb} on {@code GET /db}, without checking signatures.
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
                    body = new byte[AuthProtocol.SALT_RESPONSE_LENGTH];
                    body[0] = AuthProtocol.VERSION;
                    System.arraycopy(SALT, 0, body, 1, SALT.length);
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
        byte[] localDb = encrypt(KEYS, 2, "local");
        MemoryStorageProvider storage = new MemoryStorageProvider();
        storage.save(localDb);

        try (Server server = new Server(remoteDb)) {
            ClientValue<PasswordBlob> loaded = server.client(storage).load();
            Assert.assertEquals(server.dbRequests.get(), 1);
            Assert.assertTrue(loaded.isFromLocalStorage());
            Assert.assertEquals(loaded.getValue(), data("local"));
            Assert.assertSame(storage.load(), localDb);
        }
    }

    @Test
    public void testRollbackReason() throws Exception {
        MemoryStorageProvider storage = new MemoryStorageProvider();
        storage.save(encrypt(KEYS, 2, "local"));
        try (Server server = new Server(encrypt(KEYS, 1, "remote"))) {
            Assert.assertEquals(server.client(storage).load().getLocalReason(),
                                ClientValue.LocalReason.SERVER_COPY_OLDER);
        }
    }

    @Test
    public void testUnverifiedRemoteWithoutLocalCopy() throws Exception {
        MemoryStorageProvider storage = new MemoryStorageProvider();

        try (Server server = new Server(encrypt(OTHER_PASSWORD_KEYS, 1, "remote"))) {
            Assert.expectThrows(WrongPasswordException.class, server.client(storage)::load);
            Assert.assertEquals(server.dbRequests.get(), 1);
            Assert.assertNull(storage.load());
        }
    }

    @Test
    public void testVerifiedRemoteIsSaved() throws Exception {
        MemoryStorageProvider storage = new MemoryStorageProvider();
        storage.save(encrypt(KEYS, 2, "local"));
        // same revision: e.g. another client saved its own change on top of the same state
        byte[] remoteDb = encrypt(KEYS, 2, "remote");

        try (Server server = new Server(remoteDb)) {
            ClientValue<PasswordBlob> loaded = server.client(storage).load();
            Assert.assertFalse(loaded.isFromLocalStorage());
            Assert.assertEquals(loaded.getValue(), data("remote"));
            Assert.assertEquals(storage.load(), remoteDb);
        }
    }

    @Test
    public void testSaveIncrementsRevision() throws Exception {
        MemoryStorageProvider storage = new MemoryStorageProvider();
        try (Server server = new Server(encrypt(KEYS, 41, "remote"))) {
            PasswordClient client = server.client(storage);
            client.load();
            client.save(data("new"));
            DecryptedBlob<PasswordBlob> saved = BlobCodec.decrypt(new ObjectMapper(), KEYS, storage.load(), PasswordBlob.class);
            Assert.assertEquals(saved.getRevision(), 42);
        }
    }
}
