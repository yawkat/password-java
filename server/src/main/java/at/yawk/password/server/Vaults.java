package at.yawk.password.server;

import at.yawk.password.AuthProtocol;
import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.Property;
import jakarta.inject.Inject;
import java.io.File;
import java.io.IOException;
import java.util.function.LongSupplier;

/**
 * The vaults of the server, each with its own registration, database, nonces and backoff: the password vault in the
 * data directory, and the 2FA vault (paths below {@link AuthProtocol#TOTP_VAULT_PREFIX}) in its {@code totp}
 * subdirectory, created when the 2FA vault is registered. The protocol of both is the same. They are independent:
 * the 2FA vault has its own password, so the master password doesn't open it.
 *
 * <p>Eagerly created ({@link Context}) so that problems with the data directory show up at startup rather than on the
 * first request.
 *
 * @author yawkat
 */
@Context
public class Vaults {
    /**
     * Directory holding the database versions and the registration.
     */
    public static final String DATA_DIR_PROPERTY = "password.data-dir";

    final DatabaseState passwords;
    final DatabaseState totp;

    @Inject
    Vaults(@Property(name = DATA_DIR_PROPERTY, defaultValue = ".") String dataDirectory) throws IOException {
        passwords = new DatabaseState(dataDirectory);
        totp = new DatabaseState(new File(dataDirectory, "totp"), false);
    }

    /**
     * @return The vault that a request path belongs to
     */
    DatabaseState forPath(String path) {
        return path.startsWith(AuthProtocol.TOTP_VAULT_PREFIX + "/") ? totp : passwords;
    }

    /**
     * For tests: the clock of both vaults.
     */
    void setClock(LongSupplier clock) {
        passwords.clock = clock;
        totp.clock = clock;
    }
}
