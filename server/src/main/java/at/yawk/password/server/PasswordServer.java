package at.yawk.password.server;

import at.yawk.password.LocalStorageProvider;
import java.net.InetSocketAddress;
import lombok.experimental.UtilityClass;

/**
 * @author yawkat
 */
public interface PasswordServer extends AutoCloseable {
    void setStorageProvider(LocalStorageProvider storageProvider);

    void bind(int port);

    void bind(InetSocketAddress address);

    @UtilityClass
    class Factory {
        public static PasswordServer create() {
            return new PasswordServerImpl();
        }
    }
}
