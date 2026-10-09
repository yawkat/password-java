package at.yawk.password.client;

import java.util.function.UnaryOperator;
import org.jetbrains.annotations.Nullable;

/**
 * Holds the decrypted data of a vault and persists modifications through a {@link VaultClient}. The subclasses add
 * the modifications of their data: {@link PasswordStore} and {@link OtpStore}.
 * <p>
 * The data is copy-on-write: every modification builds new data, saves it, and only replaces the current state once
 * the save succeeded. Mutating methods block (key derivation, network) and must not be called from the UI thread; the
 * getters may be called from any thread.
 *
 * @param <T> The data of the vault
 * @author yawkat
 */
public abstract class VaultStore<T> {
    private final VaultClient<T> client;
    private volatile T data;
    @Nullable private volatile ClientValue.LocalReason localReason;

    VaultStore(VaultClient<T> client, T data, @Nullable ClientValue.LocalReason localReason) {
        this.client = client;
        this.data = data;
        this.localReason = localReason;
    }

    /**
     * @return Empty data, for a vault that doesn't exist yet
     */
    abstract T emptyData();

    T getData() {
        return data;
    }

    /**
     * @return Whether the current data is the local copy rather than the server copy, see {@link #getLocalReason()}.
     */
    public boolean isFromLocalStorage() {
        return localReason != null;
    }

    /**
     * @return Why the current data is the local copy, or {@code null} if it is the server copy.
     */
    @Nullable
    public ClientValue.LocalReason getLocalReason() {
        return localReason;
    }

    public synchronized void reload() throws Exception {
        ClientValue<T> value = client.load();
        data = value.getValue() == null ? emptyData() : value.getValue();
        localReason = value.getLocalReason();
    }

    /**
     * Save the data that the operation builds from the current data, which it must not modify. The current data is
     * only replaced once the save succeeded.
     */
    synchronized void modify(UnaryOperator<T> operation) throws Exception {
        T modified = operation.apply(data);
        client.save(modified);
        data = modified;
        // the remote now has our state, whatever it had before
        localReason = null;
    }
}
