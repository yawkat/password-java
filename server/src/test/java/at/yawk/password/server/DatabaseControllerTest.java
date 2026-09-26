package at.yawk.password.server;

import at.yawk.password.HashUtil;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HexFormat;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Checks the HTTP contract that {@code DatabaseClient} relies on.
 */
public class DatabaseControllerTest {
    private final HttpClient http = HttpClient.newHttpClient();
    private TestServer server;

    @BeforeMethod
    public void open() throws Exception {
        server = TestServer.start();
    }

    @AfterMethod
    public void close() {
        server.close();
    }

    private HttpResponse<byte[]> send(String method, String path, String token, byte[] body) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(server.getUrl() + path))
                .method(method, body == null ?
                        HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body))
                // what HttpURLConnection sends by default when writing a body
                .header("Content-Type", "application/x-www-form-urlencoded");
        if (token != null) {
            request.header("X-Auth-Token", token);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    private String token(byte[] secret) throws Exception {
        HttpResponse<byte[]> challenge = send("GET", "/challenge", null, null);
        Assert.assertEquals(challenge.statusCode(), 200);
        Assert.assertEquals(challenge.body().length, 32);
        return HexFormat.of().withUpperCase().formatHex(HashUtil.sha512(secret, challenge.body()));
    }

    private static void assertStatus(HttpResponse<byte[]> response, int status) {
        Assert.assertEquals(response.statusCode(), status);
        if (status != 200) {
            Assert.assertEquals(response.body().length, 0);
        }
    }

    @Test
    public void testSharedSecret() throws Exception {
        assertStatus(send("GET", "/challenge", null, null), 404);

        byte[] secret = HashUtil.generateRandomBytes(64);
        HttpResponse<byte[]> put = send("PUT", "/shared-secret", null, secret);
        assertStatus(put, 200);
        Assert.assertEquals(put.body().length, 0);

        // the secret can only be set once
        assertStatus(send("PUT", "/shared-secret", null, HashUtil.generateRandomBytes(64)), 403);
        assertStatus(send("PUT", "/db", token(secret), new byte[]{ 1 }), 200);
    }

    @Test
    public void testDatabase() throws Exception {
        byte[] secret = HashUtil.generateRandomBytes(64);
        assertStatus(send("PUT", "/shared-secret", null, secret), 200);

        assertStatus(send("GET", "/db", token(secret), null), 404);

        // arbitrary bytes, which are not valid form data despite the content type, and larger than Micronaut's default
        // 10MB request limits
        byte[] db = HashUtil.generateRandomBytes(20_000_000);
        HttpResponse<byte[]> put = send("PUT", "/db", token(secret), db);
        assertStatus(put, 200);
        Assert.assertEquals(put.body().length, 0);

        HttpResponse<byte[]> get = send("GET", "/db", token(secret).toLowerCase(), null);
        assertStatus(get, 200);
        Assert.assertEquals(get.body(), db);

        // an empty body is stored as an empty database
        assertStatus(send("PUT", "/db", token(secret), new byte[0]), 200);
        HttpResponse<byte[]> getEmpty = send("GET", "/db", token(secret), null);
        assertStatus(getEmpty, 200);
        Assert.assertEquals(getEmpty.body().length, 0);
    }

    @Test
    public void testInvalidTokens() throws Exception {
        byte[] secret = HashUtil.generateRandomBytes(64);
        assertStatus(send("PUT", "/shared-secret", null, secret), 200);
        assertStatus(send("PUT", "/db", token(secret), new byte[]{ 1, 2, 3 }), 200);

        assertStatus(send("GET", "/db", null, null), 403);
        assertStatus(send("GET", "/db", "not hex", null), 403);
        assertStatus(send("GET", "/db", token(HashUtil.generateRandomBytes(64)), null), 403);
        assertStatus(send("PUT", "/db", null, new byte[]{ 4 }), 403);

        // tokens are single use
        String token = token(secret);
        assertStatus(send("GET", "/db", token, null), 200);
        assertStatus(send("GET", "/db", token, null), 403);
        assertStatus(send("PUT", "/db", token, new byte[]{ 4 }), 403);

        Assert.assertEquals(send("GET", "/db", token(secret), null).body(), new byte[]{ 1, 2, 3 });
    }
}
