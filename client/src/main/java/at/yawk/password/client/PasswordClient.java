package at.yawk.password.client;

import at.yawk.password.LocalStorageProvider;
import at.yawk.password.model.PasswordBlob;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.InetSocketAddress;

/**
 * @author yawkat
 */
public interface PasswordClient extends AutoCloseable {
    static PasswordClient create() {
        return new PasswordClientImpl();
    }

    default void setRemote(String host, int port) {
        setRemote(new InetSocketAddress(host, port));
    }

    void setRemote(InetSocketAddress address);

    void setLocalStorageProvider(LocalStorageProvider localStorageProvider);

    void setObjectMapper(ObjectMapper objectMapper);

    void setPassword(byte[] password);

    ClientValue<PasswordBlob> load() throws Exception;

    void save(PasswordBlob data) throws Exception;
}
