package at.yawk.password.server;

import at.yawk.password.HashUtil;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Checks the HTTP contract that {@code DatabaseClient} relies on. {@code ClientServerTest} and {@code PasswordStoreTest}
 * cover the real client against the real server.
 */
public class DatabaseControllerTest {
    private TestServer server;
    private HttpClient httpClient;
    private BlockingHttpClient client;

    @BeforeMethod
    public void open() throws Exception {
        server = TestServer.start();
        httpClient = HttpClient.create(URI.create(server.getUrl()).toURL());
        client = httpClient.toBlocking();
    }

    @AfterMethod
    public void close() {
        httpClient.close();
        server.close();
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<byte[]> send(MutableHttpRequest<?> request) {
        try {
            return client.exchange(request, byte[].class);
        } catch (HttpClientResponseException e) {
            return (HttpResponse<byte[]>) e.getResponse();
        }
    }

    private HttpStatus getDb(String token) {
        MutableHttpRequest<?> request = HttpRequest.GET("/db");
        if (token != null) {
            request.header("X-Auth-Token", token);
        }
        return send(request).getStatus();
    }

    private byte[] getDbBody(String token) {
        HttpResponse<byte[]> response = send(HttpRequest.GET("/db").header("X-Auth-Token", token));
        Assert.assertEquals(response.getStatus(), HttpStatus.OK);
        // an empty body comes back as absent
        return response.getBody().orElse(new byte[0]);
    }

    private HttpStatus put(String path, String token, byte[] body) {
        MutableHttpRequest<byte[]> request = HttpRequest.PUT(path, body).contentType(MediaType.APPLICATION_OCTET_STREAM_TYPE);
        if (token != null) {
            request.header("X-Auth-Token", token);
        }
        HttpResponse<byte[]> response = send(request);
        if (response.getStatus() == HttpStatus.OK) {
            Assert.assertTrue(response.getBody().isEmpty());
        }
        return response.getStatus();
    }

    private String token(byte[] secret) {
        byte[] challenge = client.retrieve(HttpRequest.GET("/challenge"), byte[].class);
        Assert.assertEquals(challenge.length, 32);
        return HexFormat.of().withUpperCase().formatHex(HashUtil.sha512(secret, challenge));
    }

    private byte[] setSecret() {
        byte[] secret = HashUtil.generateRandomBytes(64);
        Assert.assertEquals(put("/shared-secret", null, secret), HttpStatus.OK);
        return secret;
    }

    @Test
    public void testSharedSecret() {
        Assert.assertEquals(send(HttpRequest.GET("/challenge")).getStatus(), HttpStatus.NOT_FOUND);

        byte[] secret = setSecret();

        // the secret can only be set once
        Assert.assertEquals(put("/shared-secret", null, HashUtil.generateRandomBytes(64)), HttpStatus.FORBIDDEN);
        Assert.assertEquals(put("/db", token(secret), new byte[]{ 1 }), HttpStatus.OK);
    }

    @Test
    public void testDatabase() {
        byte[] secret = setSecret();

        Assert.assertEquals(getDb(token(secret)), HttpStatus.NOT_FOUND);

        // arbitrary bytes, close to the 4MB request limit
        byte[] db = HashUtil.generateRandomBytes(4_000_000);
        Assert.assertEquals(put("/db", token(secret), db), HttpStatus.OK);
        Assert.assertEquals(getDbBody(token(secret).toLowerCase()), db);

        // an empty body is stored as an empty database
        Assert.assertEquals(put("/db", token(secret), new byte[0]), HttpStatus.OK);
        Assert.assertEquals(getDbBody(token(secret)).length, 0);
    }

    @Test
    public void testInvalidTokens() {
        byte[] secret = setSecret();
        Assert.assertEquals(put("/db", token(secret), new byte[]{ 1, 2, 3 }), HttpStatus.OK);

        Assert.assertEquals(getDb(null), HttpStatus.FORBIDDEN);
        Assert.assertEquals(getDb("not hex"), HttpStatus.FORBIDDEN);
        Assert.assertEquals(getDb(token(HashUtil.generateRandomBytes(64))), HttpStatus.FORBIDDEN);
        Assert.assertEquals(put("/db", null, new byte[]{ 4 }), HttpStatus.FORBIDDEN);

        // tokens are single use
        String token = token(secret);
        Assert.assertEquals(getDb(token), HttpStatus.OK);
        Assert.assertEquals(getDb(token), HttpStatus.FORBIDDEN);
        Assert.assertEquals(put("/db", token, new byte[]{ 4 }), HttpStatus.FORBIDDEN);

        Assert.assertEquals(getDbBody(token(secret)), new byte[]{ 1, 2, 3 });
    }

    /**
     * The auth filters only apply to routed requests, so requests that match no route get the usual 404 and 405.
     */
    @Test
    public void testUnrouted() {
        setSecret();
        Assert.assertEquals(send(HttpRequest.GET("/nonexistent")).getStatus(), HttpStatus.NOT_FOUND);
        Assert.assertEquals(send(HttpRequest.POST("/db", new byte[]{ 1 })).getStatus(), HttpStatus.METHOD_NOT_ALLOWED);
        Assert.assertEquals(send(HttpRequest.POST("/shared-secret", new byte[]{ 1 })).getStatus(),
                            HttpStatus.METHOD_NOT_ALLOWED);
    }

    @Test
    public void testTooLarge() {
        byte[] secret = setSecret();
        Assert.assertEquals(put("/db", token(secret), new byte[5_000_000]), HttpStatus.REQUEST_ENTITY_TOO_LARGE);
    }

    /**
     * Unauthorized uploads are rejected before their body is read, so they can't make the server buffer it.
     *
     * <p>Uses the JDK client, because it can send {@code Expect: 100-continue} and stream a lazily generated body.
     */
    @Test
    public void testUnauthorizedUploads() throws Exception {
        byte[] secret = setSecret();

        // just under the 4MB limit, so that only the auth check can reject it
        long size = 4_000_000;
        Supplier<InputStream> zeros = () -> new InputStream() {
            long remaining = size;

            @Override
            public int read() {
                return remaining-- > 0 ? 0 : -1;
            }

            @Override
            public int read(byte[] b, int off, int len) {
                if (remaining <= 0) {
                    return -1;
                }
                int n = (int) Math.min(len, remaining);
                Arrays.fill(b, off, off + n, (byte) 0);
                remaining -= n;
                return n;
            }
        };
        try (java.net.http.HttpClient jdkClient = java.net.http.HttpClient.newHttpClient()) {
            for (boolean expectContinue : new boolean[]{ true, false }) {
                List<CompletableFuture<java.net.http.HttpResponse<Void>>> responses = new ArrayList<>();
                for (int i = 0; i < 8; i++) {
                    for (String path : new String[]{ "/db", "/shared-secret" }) {
                        responses.add(jdkClient.sendAsync(
                                java.net.http.HttpRequest.newBuilder(URI.create(server.getUrl() + path))
                                        .PUT(java.net.http.HttpRequest.BodyPublishers.fromPublisher(
                                                java.net.http.HttpRequest.BodyPublishers.ofInputStream(zeros), size))
                                        .expectContinue(expectContinue)
                                        .build(),
                                java.net.http.HttpResponse.BodyHandlers.discarding()));
                    }
                }
                for (CompletableFuture<java.net.http.HttpResponse<Void>> response : responses) {
                    Assert.assertEquals(response.get().statusCode(), 403);
                }
            }
        }

        // the server still works normally
        Assert.assertEquals(put("/db", token(secret), new byte[]{ 1 }), HttpStatus.OK);
        Assert.assertEquals(getDbBody(token(secret)), new byte[]{ 1 });
    }
}
