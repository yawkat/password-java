package at.yawk.password.client;

import at.yawk.password.MemoryStorageProvider;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.server.TestServer;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * The client against the real server: registration, migration, rollback and clock skew.
 */
public class ProtocolTest {
    private static final byte[] PASSWORD = "correct horse".getBytes(StandardCharsets.UTF_8);

    private TestServer server;

    @BeforeMethod
    public void open() throws Exception {
        server = TestServer.start();
    }

    @AfterMethod
    public void close() {
        server.close();
    }

    private PasswordClient client(MemoryStorageProvider storage, byte[] password) {
        return new PasswordClient(server.getUrl(), storage, password);
    }

    private static PasswordBlob data(String name) {
        return BlobCodecTest.blob(0, name, "value").getData();
    }

    private boolean registered() throws IOException {
        return new DatabaseClient(server.getUrl()).getInstallSalt() != null;
    }

    @Test
    public void testLoadDoesNotRegister() throws Exception {
        PasswordClient client = client(new MemoryStorageProvider(), PASSWORD);
        ClientValue<PasswordBlob> loaded = client.load();
        Assert.assertNull(loaded.getValue());
        Assert.assertEquals(loaded.getLocalReason(), ClientValue.LocalReason.NOT_ON_SERVER);
        Assert.assertFalse(registered());

        client.save(data("a"));
        Assert.assertTrue(registered());
        Assert.assertTrue(Files.exists(server.getDataDirectory().resolve("verifier")));
    }

    @Test
    public void testMigration() throws Exception {
        // the old server's secret, deleted on registration
        Files.write(server.getDataDirectory().resolve("shared-secret"), new byte[8]);
        MemoryStorageProvider storage = new MemoryStorageProvider();
        storage.save(LegacyBlobTest.fixture());

        PasswordClient client = client(storage, LegacyBlobTest.PASSWORD);
        ClientValue<PasswordBlob> loaded = client.load();
        Assert.assertEquals(loaded.getLocalReason(), ClientValue.LocalReason.NOT_ON_SERVER);
        Assert.assertEquals(loaded.getValue().getPasswords().size(), 3);
        Assert.assertFalse(registered());

        client.save(loaded.getValue());
        Assert.assertTrue(registered());
        Assert.assertFalse(Files.exists(server.getDataDirectory().resolve("shared-secret")));
        Assert.assertNotNull(BlobCodec.installSalt(storage.load()), "local copy is in the new format");

        // a new device only needs the password
        ClientValue<PasswordBlob> fresh = client(new MemoryStorageProvider(), LegacyBlobTest.PASSWORD).load();
        Assert.assertNull(fresh.getLocalReason());
        Assert.assertEquals(fresh.getValue(), loaded.getValue());
    }

    @Test
    public void testWrongPassword() throws Exception {
        MemoryStorageProvider storage = new MemoryStorageProvider();
        PasswordClient client = client(storage, PASSWORD);
        client.load();
        client.save(data("a"));

        // rejected by the server, and no local copy
        IOException e = Assert.expectThrows(IOException.class,
                                            () -> client(new MemoryStorageProvider(), "wrong".getBytes()).load());
        Assert.assertTrue(e.getMessage().contains("403"), e.getMessage());
        // rejected by the server, and the local copy doesn't decrypt
        Assert.expectThrows(WrongPasswordException.class, () -> client(storage, "wrong".getBytes()).load());
    }

    @Test
    public void testRollback() throws Exception {
        MemoryStorageProvider storage = new MemoryStorageProvider();
        PasswordClient client = client(storage, PASSWORD);
        client.load();
        client.save(data("old"));
        byte[] old = storage.load();
        client.save(data("new"));

        // the server (or someone with the keys) puts the old version back
        KeyMaterial keys = KeyMaterial.derive(PASSWORD, BlobCodec.installSalt(old));
        new DatabaseClient(server.getUrl()).putDatabase(keys, old);

        ClientValue<PasswordBlob> loaded = client(storage, PASSWORD).load();
        Assert.assertEquals(loaded.getLocalReason(), ClientValue.LocalReason.SERVER_COPY_OLDER);
        Assert.assertEquals(loaded.getValue(), data("new"));
        // a device without local copy can't tell
        Assert.assertEquals(client(new MemoryStorageProvider(), PASSWORD).load().getValue(), data("old"));
    }

    @Test
    public void testOffline() throws Exception {
        MemoryStorageProvider storage = new MemoryStorageProvider();
        PasswordClient client = client(storage, PASSWORD);
        client.load();
        client.save(data("a"));

        PasswordClient offline = new PasswordClient("http://127.0.0.1:1", storage, PASSWORD);
        ClientValue<PasswordBlob> loaded = offline.load();
        Assert.assertEquals(loaded.getLocalReason(), ClientValue.LocalReason.SERVER_UNAVAILABLE);
        Assert.assertEquals(loaded.getValue(), data("a"));
        // saving offline keeps the change locally
        Assert.expectThrows(IOException.class, () -> offline.save(data("b")));
        Assert.assertEquals(BlobCodec.decrypt(new ObjectMapper(), KeyMaterial.derive(
                PASSWORD, BlobCodec.installSalt(storage.load())), storage.load()).getData(), data("b"));
    }

    @Test
    public void testClockSkew() throws Exception {
        PasswordClient client = client(new MemoryStorageProvider(), PASSWORD);
        client.load();
        client.save(data("a"));

        // the client retries with the server's clock (from the Date header)
        server.setClockOffset(10 * 60_000);
        Assert.assertEquals(client(new MemoryStorageProvider(), PASSWORD).load().getValue(), data("a"));
        client.save(data("b"));
        server.setClockOffset(-10 * 60_000);
        Assert.assertEquals(client(new MemoryStorageProvider(), PASSWORD).load().getValue(), data("b"));
    }
}
