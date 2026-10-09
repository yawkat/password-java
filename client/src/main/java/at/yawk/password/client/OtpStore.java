package at.yawk.password.client;

import at.yawk.password.model.OtpAccount;
import at.yawk.password.model.OtpBlob;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.UnaryOperator;
import org.jetbrains.annotations.Nullable;

/**
 * Holds the decrypted 2FA vault and persists modifications through a {@link VaultClient}, see {@link VaultStore}.
 * Accounts are identified by {@link OtpAccount#getId()} and treated as immutable: to change one, pass a modified copy
 * to {@link #update}.
 *
 * @author yawkat
 */
public final class OtpStore extends VaultStore<OtpBlob> {
    private OtpStore(VaultClient<OtpBlob> client, OtpBlob blob, @Nullable ClientValue.LocalReason localReason) {
        super(client, blob, localReason);
    }

    /**
     * Load the vault using the given client.
     *
     * @return The store, or {@code null} if there is no vault yet (neither remote nor local).
     */
    @Nullable
    public static OtpStore open(VaultClient<OtpBlob> client) throws Exception {
        ClientValue<OtpBlob> value = client.load();
        if (value.getValue() == null) {
            return null;
        }
        return new OtpStore(client, value.getValue(), value.getLocalReason());
    }

    /**
     * Create an empty store. Nothing is saved until the first modification.
     */
    public static OtpStore createEmpty(VaultClient<OtpBlob> client) {
        return new OtpStore(client, new OtpBlob(), null);
    }

    @Override
    OtpBlob emptyData() {
        return new OtpBlob();
    }

    public List<OtpAccount> getAccounts() {
        return Collections.unmodifiableList(getData().getAccounts());
    }

    /**
     * Add accounts at the end, e.g. from an import, with a single save.
     *
     * @throws IllegalArgumentException if an account has the id of another one
     */
    public void addAll(Collection<OtpAccount> added) throws Exception {
        modifyAccounts(accounts -> {
            for (OtpAccount account : added) {
                if (indexOf(accounts, account.getId()) >= 0) {
                    throw new IllegalArgumentException("Duplicate account id");
                }
                accounts.add(account);
            }
            return accounts;
        });
    }

    public void add(OtpAccount account) throws Exception {
        addAll(List.of(account));
    }

    /**
     * Replace the account with the same id.
     */
    public void update(OtpAccount account) throws Exception {
        modifyAccounts(accounts -> {
            accounts.set(existingIndex(accounts, account.getId()), account);
            return accounts;
        });
    }

    public void delete(String id) throws Exception {
        modifyAccounts(accounts -> {
            accounts.remove(existingIndex(accounts, id));
            return accounts;
        });
    }

    private void modifyAccounts(UnaryOperator<List<OtpAccount>> operation) throws Exception {
        modify(blob -> {
            OtpBlob copy = new OtpBlob();
            copy.setAccounts(operation.apply(new ArrayList<>(blob.getAccounts())));
            return copy;
        });
    }

    private static int existingIndex(List<OtpAccount> accounts, String id) {
        int index = indexOf(accounts, id);
        if (index < 0) {
            throw new IllegalStateException("Account is not part of this store");
        }
        return index;
    }

    private static int indexOf(List<OtpAccount> accounts, String id) {
        for (int i = 0; i < accounts.size(); i++) {
            if (accounts.get(i).getId().equals(id)) {
                return i;
            }
        }
        return -1;
    }
}
