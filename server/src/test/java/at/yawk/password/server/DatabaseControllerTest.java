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
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CompletableFuture;
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
     * {@code HttpURLConnection}, and so {@code DatabaseClient}, sends bodies as
     * {@code application/x-www-form-urlencoded}. They must be stored as raw bytes, not decoded as form data.
     */
    @Test
    public void testFormContentType() throws Exception {
        byte[] secret = setSecret();
        byte[] db = HashUtil.generateRandomBytes(100_000);
        // the JDK client, because the Micronaut client would form-encode the body
        try (java.net.http.HttpClient jdkClient = java.net.http.HttpClient.newHttpClient()) {
            int status = jdkClient.send(
                    java.net.http.HttpRequest.newBuilder(URI.create(server.getUrl() + "/db"))
                            .PUT(java.net.http.HttpRequest.BodyPublishers.ofByteArray(db))
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .header("X-Auth-Token", token(secret))
                            .build(),
                    java.net.http.HttpResponse.BodyHandlers.discarding()).statusCode();
            Assert.assertEquals(status, 200);
        }
        Assert.assertEquals(getDbBody(token(secret)), db);
    }

    /**
     * The auth filters only apply to routed requests, so requests that match no route get the usual 404 and 405.
     */
    @Test
    public void testUnrouted() throws Exception {
        setSecret();
        Assert.assertEquals(send(HttpRequest.GET("/nonexistent")).getStatus(), HttpStatus.NOT_FOUND);
        Assert.assertEquals(send(HttpRequest.POST("/db", new byte[]{ 1 })).getStatus(), HttpStatus.METHOD_NOT_ALLOWED);
        Assert.assertEquals(send(HttpRequest.DELETE("/db")).getStatus(), HttpStatus.METHOD_NOT_ALLOWED);
        Assert.assertEquals(send(HttpRequest.POST("/shared-secret", new byte[]{ 1 })).getStatus(),
                            HttpStatus.METHOD_NOT_ALLOWED);
        // raw paths, which the Micronaut client would normalize or misread
        Assert.assertEquals(rawStatus("/DB"), 404);
        Assert.assertEquals(rawStatus("/%64b"), 404);
        Assert.assertEquals(rawStatus("//db"), 404);
    }

    private int rawStatus(String path) throws Exception {
        try (java.net.http.HttpClient jdkClient = java.net.http.HttpClient.newHttpClient()) {
            return jdkClient.send(java.net.http.HttpRequest.newBuilder(URI.create(server.getUrl() + path)).build(),
                                  java.net.http.HttpResponse.BodyHandlers.discarding()).statusCode();
        }
    }

    /**
     * Routes that Micronaut also serves under other methods or paths are filtered too.
     */
    @Test
    public void testRouteVariantsAreFiltered() {
        byte[] secret = setSecret();
        Assert.assertEquals(put("/db", token(secret), new byte[]{ 1 }), HttpStatus.OK);

        // HEAD is routed to GET /db
        Assert.assertEquals(send(HttpRequest.HEAD("/db")).getStatus(), HttpStatus.FORBIDDEN);
        String token = token(secret);
        Assert.assertEquals(send(HttpRequest.HEAD("/db").header("X-Auth-Token", token)).getStatus(), HttpStatus.OK);
        Assert.assertEquals(getDb(token), HttpStatus.FORBIDDEN);

        // trailing slashes are routed too
        Assert.assertEquals(send(HttpRequest.GET("/db/")).getStatus(), HttpStatus.FORBIDDEN);
        Assert.assertEquals(put("/db/", null, new byte[]{ 2 }), HttpStatus.FORBIDDEN);
        Assert.assertEquals(put("/shared-secret/", null, new byte[]{ 2 }), HttpStatus.FORBIDDEN);
        Assert.assertEquals(send(HttpRequest.GET("/db/").header("X-Auth-Token", token(secret))).getStatus(),
                            HttpStatus.OK);

        Assert.assertEquals(getDbBody(token(secret)), new byte[]{ 1 });
    }

    @Test
    public void testTooLarge() {
        byte[] secret = setSecret();
        Assert.assertEquals(put("/db", token(secret), new byte[5_000_000]), HttpStatus.REQUEST_ENTITY_TOO_LARGE);
    }

    /**
     * A lazily generated body of zeros.
     */
    private static final class ZeroBody extends InputStream {
        final long size;
        long read;

        ZeroBody(long size) {
            this.size = size;
        }

        @Override
        public int read() {
            throw new UnsupportedOperationException();
        }

        @Override
        public int read(byte[] b, int off, int len) {
            long remaining = size - read;
            if (remaining <= 0) {
                return -1;
            }
            int n = (int) Math.min(len, remaining);
            Arrays.fill(b, off, off + n, (byte) 0);
            read += n;
            return n;
        }
    }

    private static java.net.http.HttpRequest upload(String url, ZeroBody body, boolean expectContinue) {
        return java.net.http.HttpRequest.newBuilder(URI.create(url))
                .PUT(java.net.http.HttpRequest.BodyPublishers.fromPublisher(
                        java.net.http.HttpRequest.BodyPublishers.ofInputStream(() -> body), body.size))
                .expectContinue(expectContinue)
                .build();
    }

    /**
     * Unauthorized uploads are rejected before their body is read, so they can't make the server buffer it.
     *
     * <p>Uses a raw socket and the JDK client, because the Micronaut client can't send a partial body or
     * {@code Expect: 100-continue}.
     */
    @Test
    public void testUnauthorizedUploads() throws Exception {
        byte[] secret = setSecret();

        // Announce a 4MB body but send only the first 64KB: the 403 still arrives, so the server answered without
        // waiting for (let alone buffering) the body.
        for (String path : new String[]{ "/db", "/db/", "/shared-secret", "/shared-secret/" }) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", URI.create(server.getUrl()).getPort()));
                socket.setSoTimeout(10_000);
                OutputStream out = socket.getOutputStream();
                out.write(("PUT " + path + " HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4000000\r\n\r\n")
                                  .getBytes(StandardCharsets.US_ASCII));
                out.write(new byte[64 * 1024]);
                out.flush();
                String statusLine = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII)).readLine();
                Assert.assertEquals(statusLine, "HTTP/1.1 403 Forbidden", path);
            }
        }

        try (java.net.http.HttpClient jdkClient = java.net.http.HttpClient.newHttpClient()) {
            // concurrent uploads just under the 4MB limit, so that only the auth check can reject them
            for (boolean expectContinue : new boolean[]{ true, false }) {
                List<CompletableFuture<java.net.http.HttpResponse<Void>>> responses = new ArrayList<>();
                for (int i = 0; i < 8; i++) {
                    for (String path : new String[]{ "/db", "/shared-secret" }) {
                        responses.add(jdkClient.sendAsync(
                                upload(server.getUrl() + path, new ZeroBody(4_000_000), expectContinue),
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
