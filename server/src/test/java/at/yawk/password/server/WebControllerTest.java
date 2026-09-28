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
public class WebControllerTest {
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
        Assert.assertEquals(response.getHeaders().get("Content-Security-Policy"), WebController.CONTENT_SECURITY_POLICY);
        Assert.assertEquals(response.getHeaders().get("Cache-Control"), "no-store");
        return new String(response.getBody().orElseThrow(), StandardCharsets.UTF_8);
    }

    @Test
    public void index() {
        String html = getServed("/", "text/html;charset=utf-8");
        Assert.assertTrue(html.contains("src=\"web/app.js\""));
        Assert.assertTrue(html.contains("src=\"web/argon2.js\""));
    }

    @Test
    public void assets() {
        Assert.assertTrue(getServed("/web/app.js", "text/javascript;charset=utf-8").contains("argon2id"));
        Assert.assertFalse(getServed("/web/app.css", "text/css;charset=utf-8").isEmpty());
        // copied from the webjar by the build
        Assert.assertTrue(getServed("/web/argon2.js", "text/javascript;charset=utf-8").contains("argon2id"));
    }

    @Test
    public void unknownAsset() {
        Assert.assertEquals(status("/web/index.html"), HttpStatus.NOT_FOUND);
        Assert.assertEquals(status("/web/argon2.LICENSE"), HttpStatus.NOT_FOUND);
        Assert.assertEquals(status("/web/..%2Fverifier"), HttpStatus.NOT_FOUND);
    }
}
