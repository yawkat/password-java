package at.yawk.password.client;

import at.yawk.password.LocalStorageProvider;
import at.yawk.password.model.PasswordBlob;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.InetSocketAddress;
import lombok.experimental.UtilityClass;

/**
 * @author yawkat
 */
public interface PasswordClient extends AutoCloseable {
    void setRemote(String host, int port);

    void setRemote(InetSocketAddress address);

    void setLocalStorageProvider(LocalStorageProvider localStorageProvider);

    void setObjectMapper(ObjectMapper objectMapper);

    void setPassword(byte[] password);

    ClientValue<PasswordBlob> load() throws Exception;

    void save(PasswordBlob data) throws Exception;

    @UtilityClass
    class Factory {
        public static PasswordClient create() {
            return new PasswordClientImpl();
        }
    }
}
