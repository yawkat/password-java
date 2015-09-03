package at.yawk.password.client;

import at.yawk.password.HashUtil;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.PlatformDependent;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import javax.annotation.Nullable;
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

    public ClientValue<byte[]> load() throws IOException {
        try {
            return new ClientValue<>(getRemote(), false);
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
                return new ClientValue<>(local, true);
            }
        }
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
        return HashUtil.sha256(sharedSecret, requestChallenge());
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
