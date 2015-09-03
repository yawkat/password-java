package at.yawk.password.client;

import at.yawk.password.LocalStorageProvider;
import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.EncryptedBlob;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.model.ScryptParameters;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author yawkat
 */
public class PasswordClient {
    /**
     * Parameters used to derive the shared secret. This is fairly low-security and also has a low key length; the
     * shared secret is easy to get through MiM so we don't want to leak too much data through it (assuming strong
     * password).
     *
     * The salt is random - it could probably be specialized per-server but we don't do that currently.
     */
    private static final ScryptParameters SHARED_SECRET_PARAMETERS = new ScryptParameters(
            14, 8, 1, 8, "CuRdXw06VaLQhV9K".getBytes());

    private final DatabaseClient databaseClient;
    private final ObjectMapper objectMapper;
    private final byte[] password;

    public PasswordClient(String url, LocalStorageProvider localStorageProvider, byte[] password) {
        this.password = password;
        databaseClient = new DatabaseClient(localStorageProvider, url, SHARED_SECRET_PARAMETERS.runScrypt(password));
        objectMapper = new ObjectMapper();
    }

    public ClientValue<PasswordBlob> load() throws Exception {
        return databaseClient.load().map(bytes -> {
            EncryptedBlob encryptedBlob = new EncryptedBlob();
            encryptedBlob.read(bytes);
            return AesCodec.decrypt(objectMapper, password, encryptedBlob).getData();
        });
    }

    public void save(PasswordBlob blob) throws Exception {
        DecryptedBlob decrypted = new DecryptedBlob();
        decrypted.setData(blob);
        EncryptedBlob encrypted = AesCodec.encrypt(objectMapper, password, decrypted);
        databaseClient.save(encrypted.write());
    }
}
