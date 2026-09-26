package at.yawk.password;

import at.yawk.password.client.ClientValue;
import at.yawk.password.client.PasswordClient;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.model.PasswordEntry;
import at.yawk.password.server.TestServer;
import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class ClientServerTest {
    private TestServer server;

    @BeforeTest
    public void open() throws Exception {
        server = TestServer.start();
    }

    @AfterTest
    public void close() throws Exception {
        server.close();
    }

    @Test
    public void testClientServer() throws Exception {
        byte[] password = HashUtil.generateRandomBytes(100);
        LocalStorageProvider clientStorage = new MemoryStorageProvider();

        String url = server.getUrl();
        PasswordClient client = new PasswordClient(url, clientStorage, password);

        // confirm we don't start with any blob
        ClientValue<PasswordBlob> loaded = client.load();
        Assert.assertTrue(loaded.isFromLocalStorage());
        Assert.assertNull(loaded.getValue());

        // save a test blob to remote
        PasswordBlob testBlob = new PasswordBlob();
        testBlob.getPasswords().add(new PasswordEntry() {{
            setName("Name");
            setValue("Value");
        }});
        client.save(testBlob);

        // load from remote twice: once with the same client, once with a new one

        // load the test blob back from remote
        loaded = client.load();
        Assert.assertFalse(loaded.isFromLocalStorage());
        Assert.assertEquals(testBlob, loaded.getValue());

        // recreate the client to clear out any cached data
        client = new PasswordClient(url, clientStorage, password);
        // load the test blob back from remote
        loaded = client.load();
        Assert.assertFalse(loaded.isFromLocalStorage());
        Assert.assertEquals(testBlob, loaded.getValue());
    }
}
