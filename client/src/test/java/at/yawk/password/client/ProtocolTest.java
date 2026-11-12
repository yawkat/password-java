package at.yawk.password.client;

import at.yawk.password.MemoryStorageProvider;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.server.TestServer;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
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
    public void testNewerServerCopy() throws Exception {
        MemoryStorageProvider storage = new MemoryStorageProvider();
        PasswordClient client = client(storage, PASSWORD);
        client.load();
        client.save(data("old"));

        // a newer app saves a field that this one doesn't know, with a newer writer version
        byte[] local = storage.load();
        KeyMaterial keys = KeyMaterial.derive(PASSWORD, BlobCodec.installSalt(local));
        DecryptedBlob<Map<String, Object>> newer = new DecryptedBlob<>();
        newer.setData(Map.of("passwords", List.of(), "future", 1));
        newer.setRevision(5);
        newer.setMinWriterVersion(PasswordBlob.VERSIONS.getWriter() + 1);
        new DatabaseClient(server.getUrl()).putDatabase(keys, BlobCodec.encrypt(new ObjectMapper(), keys, newer));

        // shown read-only, rather than dropping the field on the next save
        PasswordClient reader = client(storage, PASSWORD);
        ClientValue<PasswordBlob> loaded = reader.load();
        Assert.assertTrue(loaded.isReadOnly());
        Assert.assertNull(loaded.getLocalReason());
        Assert.assertEquals(loaded.getValue(), new PasswordBlob());
        byte[] serverCopy = new DatabaseClient(server.getUrl()).getDatabase(keys);
        Assert.expectThrows(ReadOnlyDatabaseException.class, () -> reader.save(data("mine")));
        Assert.assertEquals(new DatabaseClient(server.getUrl()).getDatabase(keys), serverCopy);
        Assert.assertEquals(storage.load(), serverCopy, "the local copy is the server copy, not ours");
        // the store refuses before it gets to the client
        PasswordStore store = PasswordStore.open(client(storage, PASSWORD));
        Assert.assertTrue(store.isReadOnly());
        Assert.expectThrows(ReadOnlyDatabaseException.class, () -> store.add("a", "b"));
        Assert.assertEquals(store.getEntries().size(), 0);
    }

    @Test
    public void testNewerServerCopyMustNotBeIgnored() throws Exception {
        MemoryStorageProvider storage = new MemoryStorageProvider();
        PasswordClient client = client(storage, PASSWORD);
        client.load();
        client.save(data("old"));

        byte[] local = storage.load();
        KeyMaterial keys = KeyMaterial.derive(PASSWORD, BlobCodec.installSalt(local));
        DecryptedBlob<PasswordBlob> newer = new DecryptedBlob<>();
        newer.setData(new PasswordBlob());
        newer.setRevision(5);
        newer.setMinReaderVersion(PasswordBlob.VERSIONS.getReader() + 1);
        new DatabaseClient(server.getUrl()).putDatabase(keys, BlobCodec.encrypt(new ObjectMapper(), keys, newer));

        // refused, rather than falling back to the local copy and replacing the newer data with it
        Assert.expectThrows(UnreadableDatabaseException.class, () -> client(storage, PASSWORD).load());
    }

    @Test
    public void testNewerServerCopyOlderThanLocal() throws Exception {
        MemoryStorageProvider storage = new MemoryStorageProvider();
        PasswordClient client = client(storage, PASSWORD);
        client.load();
        for (int i = 0; i < 10; i++) {
            client.save(data("local " + i));
        }

        // a newer app saved a field, with a lower revision than the local copy
        KeyMaterial keys = KeyMaterial.derive(PASSWORD, BlobCodec.installSalt(storage.load()));
        DecryptedBlob<Map<String, Object>> newer = new DecryptedBlob<>();
        newer.setData(Map.of("passwords", List.of(), "future", 1));
        newer.setRevision(5);
        newer.setMinWriterVersion(PasswordBlob.VERSIONS.getWriter() + 1);
        new DatabaseClient(server.getUrl()).putDatabase(keys, BlobCodec.encrypt(new ObjectMapper(), keys, newer));

        // the local copy is shown, but saving it would replace the field on the server
        PasswordClient reader = client(storage, PASSWORD);
        ClientValue<PasswordBlob> loaded = reader.load();
        Assert.assertEquals(loaded.getLocalReason(), ClientValue.LocalReason.SERVER_COPY_OLDER);
        Assert.assertEquals(loaded.getValue(), data("local 9"));
        Assert.assertTrue(loaded.isReadOnly());
        Assert.expectThrows(ReadOnlyDatabaseException.class, () -> reader.save(data("mine")));
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
    public void testNewerLocalCopyOffline() throws Exception {
        MemoryStorageProvider storage = new MemoryStorageProvider();
        PasswordClient client = client(storage, PASSWORD);
        client.load();
        client.save(data("old"));

        // a newer app on this device saved locally, then this one was installed again
        KeyMaterial keys = KeyMaterial.derive(PASSWORD, BlobCodec.installSalt(storage.load()));
        DecryptedBlob<Map<String, Object>> newer = new DecryptedBlob<>();
        newer.setData(Map.of("passwords", List.of(), "future", 1));
        newer.setRevision(5);
        newer.setMinWriterVersion(PasswordBlob.VERSIONS.getWriter() + 1);
        storage.save(BlobCodec.encrypt(new ObjectMapper(), keys, newer));

        PasswordClient offline = new PasswordClient("http://127.0.0.1:1", storage, PASSWORD);
        ClientValue<PasswordBlob> loaded = offline.load();
        Assert.assertEquals(loaded.getLocalReason(), ClientValue.LocalReason.SERVER_UNAVAILABLE);
        Assert.assertTrue(loaded.isReadOnly());
        Assert.expectThrows(ReadOnlyDatabaseException.class, () -> offline.save(data("mine")));
    }

    @DataProvider
    public Object[][] unreadableLocalRevisions() {
        return new Object[][]{{5L}, {1L}};
    }

    @Test(dataProvider = "unreadableLocalRevisions")
    public void testUnreadableLocalCopy(long localRevision) throws Exception {
        MemoryStorageProvider storage = new MemoryStorageProvider();
        PasswordClient client = client(storage, PASSWORD);
        client.load();
        client.save(data("a"));
        client.save(data("b"));

        // a newer app saved the local copy, with a newer reader version (the server copy is at revision 2)
        KeyMaterial keys = KeyMaterial.derive(PASSWORD, BlobCodec.installSalt(storage.load()));
        DecryptedBlob<PasswordBlob> newer = new DecryptedBlob<>();
        newer.setData(data("newer"));
        newer.setRevision(localRevision);
        newer.setMinReaderVersion(PasswordBlob.VERSIONS.getReader() + 1);
        byte[] local = BlobCodec.encrypt(new ObjectMapper(), keys, newer);
        storage.save(local);

        // whatever its revision: the server copy is no later version of it, so replacing it could lose data
        Assert.expectThrows(UnreadableDatabaseException.class, () -> client(storage, PASSWORD).load());
        Assert.assertEquals(storage.load(), local);
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
                PASSWORD, BlobCodec.installSalt(storage.load())), storage.load(), PasswordBlob.class,
                PasswordBlob.VERSIONS).getData(), data("b"));
    }

    @Test
    public void testOfflineLegacyCopyIsNotSaved() throws Exception {
        MemoryStorageProvider storage = new MemoryStorageProvider();
        byte[] legacy = LegacyBlobTest.fixture();
        storage.save(legacy);

        // the install salt is unknown: saving would have to invent one that the server doesn't know
        PasswordClient offline = new PasswordClient("http://127.0.0.1:1", storage, LegacyBlobTest.PASSWORD);
        ClientValue<PasswordBlob> loaded = offline.load();
        Assert.assertEquals(loaded.getLocalReason(), ClientValue.LocalReason.SERVER_UNAVAILABLE);
        IOException e = Assert.expectThrows(IOException.class, () -> offline.save(loaded.getValue()));
        Assert.assertTrue(e.getMessage().contains("old format"), e.getMessage());
        Assert.assertSame(storage.load(), legacy);
    }

    @Test
    public void testTrailingSlash() throws Exception {
        PasswordClient client = new PasswordClient(server.getUrl() + "/", new MemoryStorageProvider(), PASSWORD);
        client.load();
        client.save(data("a"));
        Assert.assertEquals(new PasswordClient(server.getUrl() + "//", new MemoryStorageProvider(), PASSWORD)
                                    .load().getValue(), data("a"));
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
