package at.yawk.password.server;

import at.yawk.password.LocalStorageProvider;
import java.net.InetSocketAddress;

/**
 * @author yawkat
 */
public interface PasswordServer extends AutoCloseable {
    static PasswordServer create() {
        return new PasswordServerImpl();
    }

    void setStorageProvider(LocalStorageProvider storageProvider);

    default void bind(int port) {
        bind(new InetSocketAddress("0.0.0.0", port));
    }

    void bind(InetSocketAddress address);
}
