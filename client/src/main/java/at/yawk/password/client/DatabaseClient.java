package at.yawk.password.client;

import at.yawk.password.AuthProtocol;
import at.yawk.password.HashUtil;
import at.yawk.password.PlatformDependent;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Nullable;

/**
 * The HTTP side of the client: the requests of the protocol in SPEC.md, signed with a {@link KeyMaterial}.
 *
 * @author yawkat
 */
@Slf4j
class DatabaseClient {
    /**
     * Same as the server's request limit: a larger response is not a database.
     */
    static final int MAX_RESPONSE_SIZE = 4 * 1024 * 1024;

    /**
     * Base URL without trailing slash: the signature covers the path, which must be what the server sees.
     */
    private final String url;

    /**
     * Without timeouts, a half-open connection (e.g. after switching networks) would block forever, and with it the
     * operation holding the unlocked database.
     */
    int connectTimeoutMillis = 15_000;
    int readTimeoutMillis = 60_000;

    /**
     * Difference between the server clock and ours, learned from a response rejected for its timestamp.
     */
    private volatile long clockOffsetMillis = 0;

    DatabaseClient(String url) {
        while (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        this.url = url;
    }

    /**
     * @return The install salt, or {@code null} if the server has no registration yet.
     */
    @Nullable
    byte[] getInstallSalt() throws IOException {
        byte[] response;
        try {
            response = send("GET", "/salt", null, null).body;
        } catch (FileNotFoundException e) {
            return null;
        }
        if (response.length != AuthProtocol.SALT_RESPONSE_LENGTH) {
            throw new IOException("Invalid salt response");
        }
        if (response[0] != AuthProtocol.VERSION) {
            throw new IOException("Unsupported protocol version " + response[0] + ", update the client");
        }
        byte[] salt = new byte[AuthProtocol.SALT_LENGTH];
        System.arraycopy(response, 1, salt, 0, salt.length);
        return salt;
    }

    /**
     * Register the keys on a server that has no registration yet.
     *
     * @throws IOException if that fails, e.g. with 403 because the server is registered already
     */
    void register(KeyMaterial keys) throws IOException {
        byte[] body = new byte[AuthProtocol.REGISTRATION_LENGTH];
        body[0] = AuthProtocol.VERSION;
        System.arraycopy(keys.getInstallSalt(), 0, body, 1, AuthProtocol.SALT_LENGTH);
        System.arraycopy(keys.getPublicKey(), 0, body, 1 + AuthProtocol.SALT_LENGTH, AuthProtocol.PUBLIC_KEY_LENGTH);
        send("PUT", "/register", null, body);
    }

    /**
     * @throws FileNotFoundException if the server has no database yet
     */
    byte[] getDatabase(KeyMaterial keys) throws IOException {
        return sendSigned("GET", "/db", keys, null);
    }

    void putDatabase(KeyMaterial keys, byte[] data) throws IOException {
        sendSigned("PUT", "/db", keys, data);
    }

    private byte[] sendSigned(String method, String path, KeyMaterial keys, @Nullable byte[] body) throws IOException {
        Response response = send(method, path, keys, body);
        if (response.status == 401 && response.serverDate != 0) {
            // our clock is off. Retry once with the server's
            clockOffsetMillis = response.serverDate - System.currentTimeMillis();
            log.info("Server rejected the request timestamp, retrying with a clock offset of {} ms",
                     clockOffsetMillis);
            response = send(method, path, keys, body);
        }
        if (response.status == 401) {
            throw new IOException("Server returned HTTP response code: 401 (clock out of sync?) for " + path);
        }
        return response.body;
    }

    private Response send(String method, String path, @Nullable KeyMaterial keys, @Nullable byte[] body)
            throws IOException {
        log.debug("{} {}", method, path);

        URL url = new URL(this.url + path);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(connectTimeoutMillis);
        connection.setReadTimeout(readTimeoutMillis);
        connection.setRequestMethod(method);
        // A redirect is an error (below). Following one would also send the signed header to the redirect target,
        // which could replay it to the real server.
        connection.setInstanceFollowRedirects(false);
        if (keys != null) {
            long timestamp = System.currentTimeMillis() + clockOffsetMillis;
            String nonce = PlatformDependent.printHexBinary(HashUtil.generateRandomBytes(AuthProtocol.NONCE_LENGTH));
            byte[] signature = keys.sign(AuthProtocol.signingInput(
                    timestamp, nonce, method, path, body == null ? new byte[0] : body));
            connection.setRequestProperty(AuthProtocol.AUTH_HEADER,
                                          timestamp + " " + nonce + " " + PlatformDependent.printHexBinary(signature));
        }
        if (body != null) {
            connection.setDoOutput(true);
            connection.setFixedLengthStreamingMode(body.length);
            try (OutputStream out = connection.getOutputStream()) {
                out.write(body);
            }
        }
        int status = connection.getResponseCode();
        // a 401 for an unsigned request (e.g. from an authenticating proxy) is an error like any other, below
        if (status == 401 && keys != null) {
            return new Response(status, connection.getHeaderFieldDate("Date", 0), null);
        }
        // error codes are thrown by getInputStream (404 as FileNotFoundException), but other non-2xx responses such
        // as an unfollowed http -> https redirect would otherwise be returned as if they were data
        if (status < 400 && status / 100 != 2) {
            throw new IOException("Unexpected HTTP status " + status + " for " + method + " " + url +
                                  (connection.getHeaderField("Location") == null ?
                                          "" : " (redirect to " + connection.getHeaderField("Location") + ")"));
        }
        try (InputStream in = connection.getInputStream();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            byte[] buf = new byte[4096];
            int len;
            while ((len = in.read(buf)) >= 0) {
                if (out.size() + len > MAX_RESPONSE_SIZE) {
                    throw new IOException("Response too large for " + method + " " + url);
                }
                out.write(buf, 0, len);
            }
            return new Response(status, 0, out.toByteArray());
        }
    }

    @RequiredArgsConstructor
    private static final class Response {
        final int status;
        /**
         * Value of the {@code Date} header of a 401, or 0.
         */
        final long serverDate;
        final byte[] body;
    }
}
