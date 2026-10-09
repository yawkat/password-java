package at.yawk.password.client;

import org.jetbrains.annotations.Nullable;
import lombok.Value;

/**
 * @author yawkat
 */
@Value
public class ClientValue<T> {
    /**
     * The database, or {@code null} if there is none yet, neither on the server nor locally.
     */
    @Nullable private final T value;
    /**
     * Why the value is the local copy rather than the server copy, or {@code null} if it is the server copy.
     */
    @Nullable private final LocalReason localReason;

    public boolean isFromLocalStorage() {
        return localReason != null;
    }

    public enum LocalReason {
        /**
         * The server could not be reached, or refused access.
         */
        SERVER_UNAVAILABLE,
        /**
         * The server copy could not be decrypted.
         */
        SERVER_COPY_INVALID,
        /**
         * The server copy is older than the local copy: someone rolled it back, or our last upload failed.
         */
        SERVER_COPY_OLDER,
        /**
         * The server has no database (or no registration) yet. The next save uploads.
         */
        NOT_ON_SERVER,
        /**
         * The server has no registration, and the client has an exported key ({@link VaultKey#ofExportedKey}), which
         * can't create the vault again: it was reset on the server. Saves only reach the local copy, and fail. Unlock
         * with the password to create the vault again.
         */
        VAULT_RESET,
    }
}
