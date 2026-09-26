package at.yawk.password.server;

import at.yawk.password.AuthProtocol;
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
    private ServerAuth auth;

    @BeforeMethod
    public void open() throws Exception {
        server = TestServer.start();
        httpClient = HttpClient.create(URI.create(server.getUrl()).toURL());
        client = httpClient.toBlocking();
        auth = new ServerAuth();
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

    private HttpResponse<byte[]> getDb(String auth) {
        MutableHttpRequest<?> request = HttpRequest.GET("/db");
        if (auth != null) {
            request.header(AuthProtocol.AUTH_HEADER, auth);
        }
        return send(request);
    }

    private byte[] getDbBody() throws Exception {
        HttpResponse<byte[]> response = getDb(auth.header("GET", "/db", new byte[0]));
        Assert.assertEquals(response.getStatus(), HttpStatus.OK);
        return response.getBody().orElseThrow();
    }

    private HttpStatus put(String path, String auth, byte[] body) {
        MutableHttpRequest<byte[]> request = HttpRequest.PUT(path, body).contentType(MediaType.APPLICATION_OCTET_STREAM_TYPE);
        if (auth != null) {
            request.header(AuthProtocol.AUTH_HEADER, auth);
        }
        HttpResponse<byte[]> response = send(request);
        if (response.getStatus() == HttpStatus.OK) {
            Assert.assertTrue(response.getBody().isEmpty());
        }
        return response.getStatus();
    }

    private HttpStatus putDb(byte[] db) throws Exception {
        return put("/db", auth.header("PUT", "/db", db), db);
    }

    private void register() {
        Assert.assertEquals(put("/register", null, auth.registration()), HttpStatus.OK);
    }

    @Test
    public void testRegistration() throws Exception {
        Assert.assertEquals(send(HttpRequest.GET("/salt")).getStatus(), HttpStatus.NOT_FOUND);
        // unregistered: nothing to sign against
        Assert.assertEquals(getDb(auth.header("GET", "/db", new byte[0])).getStatus(), HttpStatus.FORBIDDEN);

        // malformed registrations
        Assert.assertEquals(put("/register", null, new byte[10]), HttpStatus.BAD_REQUEST);
        Assert.assertEquals(put("/register", null, new byte[0]), HttpStatus.BAD_REQUEST);
        Assert.assertEquals(put("/register", null, ServerAuth.withByte(auth.registration(), 0, 2)),
                            HttpStatus.BAD_REQUEST);

        register();
        HttpResponse<byte[]> salt = send(HttpRequest.GET("/salt"));
        Assert.assertEquals(salt.getStatus(), HttpStatus.OK);
        byte[] expected = new byte[AuthProtocol.SALT_RESPONSE_LENGTH];
        expected[0] = AuthProtocol.VERSION;
        System.arraycopy(auth.salt, 0, expected, 1, auth.salt.length);
        Assert.assertEquals(salt.getBody().orElseThrow(), expected);

        // the registration can only be set once
        Assert.assertEquals(put("/register", null, new ServerAuth().registration()), HttpStatus.FORBIDDEN);
        Assert.assertEquals(putDb(auth.database(100)), HttpStatus.OK);
    }

    @Test
    public void testDatabase() throws Exception {
        register();

        Assert.assertEquals(getDb(auth.header("GET", "/db", new byte[0])).getStatus(), HttpStatus.NOT_FOUND);

        // close to the 4MB request limit
        byte[] db = auth.database(4_000_000);
        Assert.assertEquals(putDb(db), HttpStatus.OK);
        Assert.assertEquals(getDbBody(), db);
    }

    /**
     * A migrated server still has the database of the old protocol in its data directory. It must not be served to
     * whoever registers first.
     */
    @Test
    public void testLegacyDatabaseIsNotServed() throws Exception {
        java.nio.file.Files.write(server.getDataDirectory().resolve("latest"), new byte[1000]);
        register();
        Assert.assertEquals(getDb(auth.header("GET", "/db", new byte[0])).getStatus(), HttpStatus.NOT_FOUND);
    }

    @Test
    public void testInvalidDatabase() throws Exception {
        register();
        byte[] db = auth.database(1000);
        Assert.assertEquals(putDb(new byte[0]), HttpStatus.BAD_REQUEST);
        Assert.assertEquals(putDb(Arrays.copyOf(db, AuthProtocol.BLOB_HEADER_LENGTH - 1)), HttpStatus.BAD_REQUEST);
        Assert.assertEquals(putDb(ServerAuth.withByte(db, 0, 'X')), HttpStatus.BAD_REQUEST);
        Assert.assertEquals(putDb(ServerAuth.withByte(db, AuthProtocol.BLOB_MAGIC.length, 2)), HttpStatus.BAD_REQUEST);
        // another registration's database
        Assert.assertEquals(putDb(ServerAuth.withByte(db, AuthProtocol.BLOB_INSTALL_SALT_OFFSET + 5,
                                                      db[AuthProtocol.BLOB_INSTALL_SALT_OFFSET + 5] ^ 1)),
                            HttpStatus.BAD_REQUEST);
        Assert.assertEquals(getDb(auth.header("GET", "/db", new byte[0])).getStatus(), HttpStatus.NOT_FOUND);
    }

    @Test
    public void testInvalidAuth() throws Exception {
        register();
        byte[] db = auth.database(100);
        Assert.assertEquals(putDb(db), HttpStatus.OK);

        Assert.assertEquals(getDb(null).getStatus(), HttpStatus.FORBIDDEN);
        Assert.assertEquals(getDb("not a header").getStatus(), HttpStatus.FORBIDDEN);
        Assert.assertEquals(put("/db", null, auth.database(100)), HttpStatus.FORBIDDEN);
        // wrong key
        Assert.assertEquals(getDb(new ServerAuth().header("GET", "/db", new byte[0])).getStatus(),
                            HttpStatus.FORBIDDEN);
        // signed for another method, path or body
        Assert.assertEquals(put("/db", auth.header("GET", "/db", new byte[0]), auth.database(100)),
                            HttpStatus.FORBIDDEN);
        Assert.assertEquals(getDb(auth.header("GET", "/db/", new byte[0])).getStatus(), HttpStatus.FORBIDDEN);
        byte[] other = auth.database(100);
        Assert.assertEquals(put("/db", auth.header("PUT", "/db", other), auth.database(100)), HttpStatus.FORBIDDEN);

        // requests can't be replayed
        String header = auth.header("GET", "/db", new byte[0]);
        Assert.assertEquals(getDb(header).getStatus(), HttpStatus.OK);
        Assert.assertEquals(getDb(header).getStatus(), HttpStatus.FORBIDDEN);
        header = auth.header("PUT", "/db", other);
        Assert.assertEquals(put("/db", header, other), HttpStatus.OK);
        Assert.assertEquals(put("/db", header, other), HttpStatus.FORBIDDEN);

        // stale or future timestamps
        for (long offset : new long[]{ -AuthProtocol.MAX_CLOCK_SKEW_MILLIS - 5000, AuthProtocol.MAX_CLOCK_SKEW_MILLIS + 5000 }) {
            HttpResponse<byte[]> response =
                    getDb(auth.header(System.currentTimeMillis() + offset, "GET", "/db", new byte[0]));
            Assert.assertEquals(response.getStatus(), HttpStatus.UNAUTHORIZED);
            Assert.assertTrue(response.getHeaders().contains("Date"));
        }

        Assert.assertEquals(getDbBody(), other);
    }

    @Test
    public void testBackoff() throws Exception {
        register();
        ServerAuth attacker = new ServerAuth();
        for (int i = 0; i < DatabaseState.FREE_FAILURES; i++) {
            Assert.assertEquals(getDb(attacker.header("GET", "/db", new byte[0])).getStatus(), HttpStatus.FORBIDDEN);
        }
        Assert.assertEquals(getDb(auth.header("GET", "/db", new byte[0])).getStatus(), HttpStatus.TOO_MANY_REQUESTS);
        // the backoff is 1s at first
        server.setClockOffset(1500);
        Assert.assertEquals(getDb(auth.header("GET", "/db", new byte[0])).getStatus(), HttpStatus.NOT_FOUND);
    }

    /**
     * {@code HttpURLConnection}, and so {@code DatabaseClient}, sends bodies as
     * {@code application/x-www-form-urlencoded}. They must be stored as raw bytes, not decoded as form data.
     */
    @Test
    public void testFormContentType() throws Exception {
        register();
        byte[] db = auth.database(100_000);
        // the JDK client, because the Micronaut client would form-encode the body
        try (java.net.http.HttpClient jdkClient = java.net.http.HttpClient.newHttpClient()) {
            int status = jdkClient.send(
                    java.net.http.HttpRequest.newBuilder(URI.create(server.getUrl() + "/db"))
                            .PUT(java.net.http.HttpRequest.BodyPublishers.ofByteArray(db))
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .header(AuthProtocol.AUTH_HEADER, auth.header("PUT", "/db", db))
                            .build(),
                    java.net.http.HttpResponse.BodyHandlers.discarding()).statusCode();
            Assert.assertEquals(status, 200);
        }
        Assert.assertEquals(getDbBody(), db);
    }

    /**
     * The auth filters only apply to routed requests, so requests that match no route get the usual 404 and 405.
     */
    @Test
    public void testUnrouted() throws Exception {
        register();
        Assert.assertEquals(send(HttpRequest.GET("/nonexistent")).getStatus(), HttpStatus.NOT_FOUND);
        Assert.assertEquals(send(HttpRequest.POST("/db", new byte[]{ 1 })).getStatus(), HttpStatus.METHOD_NOT_ALLOWED);
        Assert.assertEquals(send(HttpRequest.DELETE("/db")).getStatus(), HttpStatus.METHOD_NOT_ALLOWED);
        Assert.assertEquals(send(HttpRequest.POST("/register", new byte[]{ 1 })).getStatus(),
                            HttpStatus.METHOD_NOT_ALLOWED);
        // the old protocol
        Assert.assertEquals(send(HttpRequest.GET("/challenge")).getStatus(), HttpStatus.NOT_FOUND);
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
    public void testRouteVariantsAreFiltered() throws Exception {
        register();
        byte[] db = auth.database(100);
        Assert.assertEquals(putDb(db), HttpStatus.OK);

        // HEAD is routed to GET /db
        Assert.assertEquals(send(HttpRequest.HEAD("/db")).getStatus(), HttpStatus.FORBIDDEN);
        Assert.assertEquals(send(HttpRequest.HEAD("/db").header(AuthProtocol.AUTH_HEADER, auth.header("GET", "/db", new byte[0])))
                                    .getStatus(), HttpStatus.FORBIDDEN);
        Assert.assertEquals(send(HttpRequest.HEAD("/db").header(AuthProtocol.AUTH_HEADER, auth.header("HEAD", "/db", new byte[0])))
                                    .getStatus(), HttpStatus.OK);

        // trailing slashes are routed too
        Assert.assertEquals(send(HttpRequest.GET("/db/")).getStatus(), HttpStatus.FORBIDDEN);
        Assert.assertEquals(put("/db/", null, auth.database(100)), HttpStatus.FORBIDDEN);
        Assert.assertEquals(put("/register/", null, new ServerAuth().registration()), HttpStatus.FORBIDDEN);
        Assert.assertEquals(send(HttpRequest.GET("/db/").header(AuthProtocol.AUTH_HEADER, auth.header("GET", "/db/", new byte[0])))
                                    .getStatus(), HttpStatus.OK);

        Assert.assertEquals(getDbBody(), db);
    }

    @Test
    public void testTooLarge() throws Exception {
        register();
        Assert.assertEquals(putDb(auth.database(5_000_000)), HttpStatus.REQUEST_ENTITY_TOO_LARGE);
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
        register();

        // Announce a 4MB body but send only the first 64KB: the 403 still arrives, so the server answered without
        // waiting for (let alone buffering) the body.
        for (String path : new String[]{ "/db", "/db/", "/register", "/register/" }) {
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
                    for (String path : new String[]{ "/db", "/register" }) {
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
        byte[] db = auth.database(100);
        Assert.assertEquals(putDb(db), HttpStatus.OK);
        Assert.assertEquals(getDbBody(), db);
    }
}
