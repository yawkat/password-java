package at.yawk.password.client;

import at.yawk.password.MemoryStorageProvider;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class RedirectTest {
    @Test
    public void testRedirectIsNotTreatedAsData() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            // mimic a reverse proxy upgrading to https, which HttpURLConnection does not follow
            byte[] body = "Moved Permanently".getBytes();
            exchange.getResponseHeaders().add("Location", "https://127.0.0.1" + exchange.getRequestURI());
            exchange.sendResponseHeaders(301, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            MemoryStorageProvider storage = new MemoryStorageProvider();
            PasswordClient client = new PasswordClient(
                    "http://127.0.0.1:" + server.getAddress().getPort(), storage, new byte[]{ 1, 2, 3 });
            IOException e = Assert.expectThrows(IOException.class, client::load);
            Assert.assertTrue(e.getMessage().contains("301"), e.getMessage());
            Assert.assertNull(storage.load());
        } finally {
            server.stop(0);
        }
    }
}
