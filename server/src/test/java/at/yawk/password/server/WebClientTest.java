package at.yawk.password.server;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * Serving of the emergency web client. The page itself was tested by hand in a browser against a database written by
 * the Java client; its key derivation matches the values pinned in {@code KeyMaterialTest}.
 */
public class WebClientTest {
    private TestServer server;
    private HttpClient httpClient;
    private BlockingHttpClient client;

    @BeforeClass
    public void open() throws Exception {
        server = TestServer.start();
        httpClient = HttpClient.create(URI.create(server.getUrl()).toURL());
        client = httpClient.toBlocking();
    }

    @AfterClass
    public void close() {
        httpClient.close();
        server.close();
    }

    private HttpStatus status(String path) {
        try {
            return client.exchange(HttpRequest.GET(path)).getStatus();
        } catch (HttpClientResponseException e) {
            return e.getStatus();
        }
    }

    private String getServed(String path, String contentType) {
        HttpResponse<byte[]> response = client.exchange(HttpRequest.GET(path), byte[].class);
        Assert.assertEquals(response.getStatus(), HttpStatus.OK);
        Assert.assertEquals(response.getHeaders().get("Content-Type"), contentType);
        Assert.assertEquals(response.getHeaders().get("Content-Security-Policy"), WebHeadersFilter.CONTENT_SECURITY_POLICY);
        Assert.assertEquals(response.getHeaders().get("Cache-Control"), "no-store");
        return new String(response.getBody().orElseThrow(), StandardCharsets.UTF_8);
    }

    @Test
    public void index() {
        String html = getServed("/", "text/html");
        Assert.assertTrue(html.contains("src=\"app.js\""));
        Assert.assertTrue(html.contains("src=\"argon2.js\""));
    }

    @Test
    public void assets() {
        String app = getServed("/app.js", "application/javascript");
        Assert.assertTrue(app.contains("argon2id"));
        // the 2FA vault, below totp/
        Assert.assertTrue(app.contains("\"totp/\""));
        Assert.assertFalse(getServed("/app.css", "text/css").isEmpty());
        // copied from the webjar by the build
        Assert.assertTrue(getServed("/argon2.js", "application/javascript").contains("argon2id"));
    }

    @Test
    public void unknownAsset() {
        Assert.assertEquals(status("/missing.js"), HttpStatus.NOT_FOUND);
        // only web/ is served
        Assert.assertEquals(status("/application.properties"), HttpStatus.NOT_FOUND);
        Assert.assertEquals(status("/..%2Fapplication.properties"), HttpStatus.NOT_FOUND);
        Assert.assertEquals(status("/%2E%2E/application.properties"), HttpStatus.NOT_FOUND);
        Assert.assertEquals(status("/META-INF/licenses/hash-wasm/LICENSE"), HttpStatus.NOT_FOUND);
    }
}
