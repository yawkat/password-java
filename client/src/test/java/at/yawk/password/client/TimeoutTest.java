package at.yawk.password.client;

import at.yawk.password.MemoryStorageProvider;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TimeoutTest {
    @Test(timeOut = 10_000)
    public void unresponsiveServerTimesOut() throws Exception {
        // accepts connections but never answers, like a half-open connection
        try (ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            List<Socket> accepted = new ArrayList<>();
            Thread acceptor = new Thread(() -> {
                try {
                    while (true) {
                        accepted.add(server.accept());
                    }
                } catch (Exception ignored) {
                }
            });
            acceptor.setDaemon(true);
            acceptor.start();

            DatabaseClient client = new DatabaseClient(
                    new MemoryStorageProvider(), "http://127.0.0.1:" + server.getLocalPort(), new byte[]{ 1, 2, 3 });
            client.readTimeoutMillis = 500;
            Assert.expectThrows(SocketTimeoutException.class, () -> client.load(bytes -> bytes));
        }
    }

    @Test
    public void defaults() {
        DatabaseClient client = new DatabaseClient(new MemoryStorageProvider(), "http://127.0.0.1", new byte[0]);
        Assert.assertEquals(client.connectTimeoutMillis, 15_000);
        Assert.assertEquals(client.readTimeoutMillis, 60_000);
    }
}
