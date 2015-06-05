package at.yawk.password;

import at.yawk.password.client.ClientValue;
import at.yawk.password.client.PasswordClient;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.model.PasswordEntry;
import at.yawk.password.server.PasswordServer;
import java.util.concurrent.ThreadLocalRandom;
import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class ClientServerTest {
    private static final int PORT = 1234;

    private PasswordServer server;

    public static byte[] randomBytes(int len) {
        byte[] bytes = new byte[len];
        ThreadLocalRandom.current().nextBytes(bytes);
        return bytes;
    }

    @BeforeTest
    public void open() {
        server = PasswordServer.create();
        server.setStorageProvider(new MemoryStorageProvider());
        server.bind(PORT);
    }

    @AfterTest
    public void close() throws Exception {
        server.close();
    }

    @Test
    public void testClientServer() throws Exception {
        byte[] password = randomBytes(100);

        PasswordClient client = createClient(password);

        // confirm we don't start with any blob
        System.err.println("LOAD");
        ClientValue<PasswordBlob> loaded = client.load();
        Assert.assertTrue(loaded.isFromLocalStorage());
        Assert.assertNull(loaded.getValue());

        // save a test blob to remote
        System.err.println("SAVE");
        PasswordBlob testBlob = new PasswordBlob();
        testBlob.getPasswords().add(new PasswordEntry() {{
            setName("Name");
            setValue("Value");
        }});
        client.save(testBlob);

        // load from remote twice: once with the same client, once with a new one

        // load the test blob back from remote
        System.err.println("LOAD");
        loaded = client.load();
        Assert.assertFalse(loaded.isFromLocalStorage());
        Assert.assertEquals(testBlob, loaded.getValue());

        // recreate the client to clear out any cached data
        client = createClient(password);
        // load the test blob back from remote
        System.err.println("LOAD");
        loaded = client.load();
        Assert.assertFalse(loaded.isFromLocalStorage());
        Assert.assertEquals(testBlob, loaded.getValue());
    }

    private static PasswordClient createClient(byte[] password) {
        PasswordClient client = PasswordClient.create();
        client.setRemote("localhost", PORT);
        client.setPassword(password);
        return client;
    }
}
