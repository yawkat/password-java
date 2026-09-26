package at.yawk.password.client;

import at.yawk.password.HashUtil;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.PlatformDependent;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import org.jetbrains.annotations.Nullable;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * @author yawkat
 */
@Slf4j
@RequiredArgsConstructor
class DatabaseClient {
    private final LocalStorageProvider storageProvider;
    private final String url;
    private final byte[] sharedSecret;

    /**
     * Load the database, preferring the remote copy and falling back to the local copy if the remote is unreachable
     * or fails verification.
     *
     * @param parser Parses and verifies the raw database. A remote database is only saved as the local copy once
     *               this succeeds, so a remote blob that fails verification never replaces the local copy.
     */
    public <T, E extends Exception> ClientValue<T> load(ClientValue.ThrowingFunction<byte[], T, E> parser)
            throws IOException, E {
        byte[] remote;
        try {
            remote = getRemote();
        } catch (IOException e) {
            log.info("Could not get db from remote, trying local", e);

            byte[] local = storageProvider.load();
            if (local == null) {
                if ((e instanceof FileNotFoundException)) {
                    return new ClientValue<>(null, true);
                } else {
                    // rethrow remote exception
                    throw e;
                }
            } else {
                return new ClientValue<>(parser.apply(local), true);
            }
        }

        T value;
        try {
            value = parser.apply(remote);
        } catch (Exception e) {
            log.warn("Could not verify db from remote, trying local", e);

            try {
                byte[] local = storageProvider.load();
                if (local != null) {
                    return new ClientValue<>(parser.apply(local), true);
                }
            } catch (Exception localException) {
                e.addSuppressed(localException);
            }
            // rethrow remote exception
            throw e;
        }
        try {
            storageProvider.save(remote);
        } catch (IOException e) {
            log.warn("Could not save db from remote to local storage", e);
        }
        return new ClientValue<>(value, false);
    }

    public void save(byte[] data) throws IOException {
        storageProvider.save(data);
        setRemote(data);
    }

    private byte[] getRemote() throws IOException {
        return send("GET", "/db", requestToken(), null);
    }

    private void setRemote(byte[] data) throws IOException {
        send("PUT", "/db", requestToken(), data);
    }

    private byte[] requestToken() throws IOException {
        return HashUtil.sha512(sharedSecret, requestChallenge());
    }

    private byte[] requestChallenge() throws IOException {
        try {
            return send("GET", "/challenge", null, null);
        } catch (FileNotFoundException e) {
            send("PUT", "/shared-secret", null, sharedSecret);
            return requestChallenge();
        }
    }

    private byte[] send(String method, String path, @Nullable byte[] token, @Nullable byte[] body) throws IOException {
        log.debug("{} {}", method, path);

        URL url = new URL(this.url + path);
        URLConnection connection = url.openConnection();
        ((HttpURLConnection) connection).setRequestMethod(method);
        if (token != null) {
            connection.setRequestProperty("X-Auth-Token", PlatformDependent.printHexBinary(token));
        }
        if (body != null) {
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Length", String.valueOf(body.length));
            try (OutputStream out = connection.getOutputStream()) {
                out.write(body);
            }
        }
        int status = ((HttpURLConnection) connection).getResponseCode();
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
                out.write(buf, 0, len);
            }
            return out.toByteArray();
        }
    }
}
