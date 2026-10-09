package at.yawk.password.client;

import at.yawk.password.AuthProtocol;
import at.yawk.password.HashUtil;
import at.yawk.password.LocalStorageProvider;
import at.yawk.password.MemoryStorageProvider;
import at.yawk.password.model.OtpAccount;
import at.yawk.password.model.OtpBlob;
import at.yawk.password.model.PasswordBlob;
import at.yawk.password.model.PasswordEntry;
import at.yawk.password.server.TestServer;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * The 2FA vault against the real server: independent of the password vault, and opened with its password or with an
 * exported key (as the Android app does after a fingerprint).
 */
public class OtpVaultTest {
    private static final byte[] BACKUP_PASSWORD = "correct horse battery staple".getBytes(StandardCharsets.UTF_8);

    private TestServer server;

    @BeforeMethod
    public void open() throws Exception {
        server = TestServer.start();
    }

    @AfterMethod
    public void close() {
        server.close();
    }

    private static OtpAccount account(String issuer) {
        OtpAccount account = new OtpAccount();
        account.setIssuer(issuer);
        account.setSecret("JBSWY3DPEHPK3PXP");
        account.setBackupCodes("abcd-1234");
        return account;
    }

    private VaultClient<OtpBlob> withPassword(LocalStorageProvider storage) {
        return VaultClient.otp(server.getUrl(), storage, VaultKey.ofPassword(BACKUP_PASSWORD));
    }

    /**
     * A new vault, as the apps create it: after loading found none.
     */
    private static OtpStore create(VaultClient<OtpBlob> client) throws Exception {
        Assert.assertNull(OtpStore.open(client));
        return OtpStore.createEmpty(client);
    }

    private static List<String> issuers(OtpStore store) {
        return store.getAccounts().stream().map(OtpAccount::getIssuer).toList();
    }

    @Test
    public void independentOfPasswordVault() throws Exception {
        byte[] masterPassword = HashUtil.generateRandomBytes(16);
        PasswordClient passwordClient =
                new PasswordClient(server.getUrl(), new MemoryStorageProvider(), masterPassword);
        Assert.assertNull(PasswordStore.open(passwordClient));
        PasswordStore.createEmpty(passwordClient).add("github", "hunter2");

        OtpStore otp = create(withPassword(new MemoryStorageProvider()));
        otp.add(account("GitHub"));

        Assert.assertTrue(server.getDataDirectory().resolve("totp/verifier").toFile().isFile());
        Assert.assertNotEquals(new DatabaseClient(server.getUrl()).getInstallSalt(),
                               new DatabaseClient(server.getUrl(), AuthProtocol.TOTP_VAULT_PREFIX).getInstallSalt());

        // each opens with its own password only
        OtpStore reopened = OtpStore.open(withPassword(new MemoryStorageProvider()));
        Assert.assertNotNull(reopened);
        Assert.assertFalse(reopened.isFromLocalStorage());
        Assert.assertEquals(reopened.getAccounts(), otp.getAccounts());
        // the server refuses the signature (403); without a local copy that is the error
        Assert.expectThrows(IOException.class, () -> OtpStore.open(VaultClient.otp(
                server.getUrl(), new MemoryStorageProvider(), VaultKey.ofPassword(masterPassword))));
        PasswordStore reopenedPasswords = PasswordStore.open(
                new PasswordClient(server.getUrl(), new MemoryStorageProvider(), masterPassword));
        Assert.assertNotNull(reopenedPasswords);
        Assert.assertEquals(reopenedPasswords.getEntries().size(), 1);
    }

    @Test
    public void exportedKey() throws Exception {
        LocalStorageProvider storage = new MemoryStorageProvider();
        VaultClient<OtpBlob> client = withPassword(storage);
        Assert.expectThrows(IllegalStateException.class, client::exportKey);
        create(client).add(account("A"));
        byte[] exported = client.exportKey();
        Assert.assertEquals(exported.length, VaultKey.EXPORTED_LENGTH);

        // opens the vault without the password, and syncs with the server
        VaultKey key = VaultKey.ofExportedKey(exported);
        Arrays.fill(exported, (byte) 0);
        VaultClient<OtpBlob> byKey = VaultClient.otp(server.getUrl(), storage, key);
        OtpStore fingerprint = OtpStore.open(byKey);
        Assert.assertNotNull(fingerprint);
        Assert.assertEquals(issuers(fingerprint), List.of("A"));
        fingerprint.add(account("B"));
        OtpStore reopened = OtpStore.open(withPassword(new MemoryStorageProvider()));
        Assert.assertNotNull(reopened);
        Assert.assertEquals(issuers(reopened), List.of("A", "B"));

        // the same key again, exported from the client that uses it
        Assert.assertEquals(byKey.exportKey(), client.exportKey());

        // offline: the local copy
        OtpStore offline = OtpStore.open(VaultClient.otp("http://127.0.0.1:1", storage, VaultKey.ofExportedKey(
                byKey.exportKey())));
        Assert.assertNotNull(offline);
        Assert.assertEquals(offline.getLocalReason(), ClientValue.LocalReason.SERVER_UNAVAILABLE);
        Assert.assertEquals(issuers(offline), List.of("A", "B"));
    }

    /**
     * After the vault on the server was reset and created again, an exported key of the old one fails like a wrong
     * password, and never touches the new vault.
     */
    @Test
    public void exportedKeyOfAnotherVault() throws Exception {
        VaultClient<OtpBlob> old;
        byte[] exported;
        try (TestServer other = TestServer.start()) {
            old = VaultClient.otp(other.getUrl(), new MemoryStorageProvider(), VaultKey.ofPassword(BACKUP_PASSWORD));
            create(old).add(account("old"));
            exported = old.exportKey();
        }
        create(withPassword(new MemoryStorageProvider())).add(account("new"));

        VaultClient<OtpBlob> stale =
                VaultClient.otp(server.getUrl(), new MemoryStorageProvider(), VaultKey.ofExportedKey(exported));
        Assert.expectThrows(WrongPasswordException.class, () -> OtpStore.open(stale));
        OtpStore reopened = OtpStore.open(withPassword(new MemoryStorageProvider()));
        Assert.assertNotNull(reopened);
        Assert.assertEquals(issuers(reopened), List.of("new"));
    }

    /**
     * A vault that was reset on the server (here: a fresh server) is never registered again with an exported key of
     * the old one, which would take it back from whoever creates it anew. The local copy can still be read.
     */
    @Test
    public void exportedKeyNeverRegisters() throws Exception {
        LocalStorageProvider storage = new MemoryStorageProvider();
        byte[] exported;
        try (TestServer old = TestServer.start()) {
            VaultClient<OtpBlob> client = VaultClient.otp(old.getUrl(), storage, VaultKey.ofPassword(BACKUP_PASSWORD));
            create(client).add(account("A"));
            exported = client.exportKey();
        }
        DatabaseClient server = new DatabaseClient(this.server.getUrl(), AuthProtocol.TOTP_VAULT_PREFIX);

        // without a local copy, there is nothing to open
        Assert.expectThrows(WrongPasswordException.class, () -> OtpStore.open(VaultClient.otp(
                this.server.getUrl(), new MemoryStorageProvider(), VaultKey.ofExportedKey(exported))));

        // with one, it opens, but saving doesn't register: the change only reaches the local copy
        VaultClient<OtpBlob> client = VaultClient.otp(this.server.getUrl(), storage, VaultKey.ofExportedKey(exported));
        OtpStore store = OtpStore.open(client);
        Assert.assertNotNull(store);
        Assert.assertEquals(store.getLocalReason(), ClientValue.LocalReason.VAULT_RESET);
        Assert.assertEquals(issuers(store), List.of("A"));
        Assert.expectThrows(WrongPasswordException.class, () -> store.add(account("B")));
        Assert.assertNull(server.getInstallSalt());
        OtpStore reopened = OtpStore.open(
                VaultClient.otp(this.server.getUrl(), storage, VaultKey.ofExportedKey(exported)));
        Assert.assertNotNull(reopened);
        Assert.assertEquals(issuers(reopened), List.of("A", "B"));
    }

    /**
     * A vault created again after a reset, from a device with a local copy, gets a new install salt: the exported keys
     * of the old vault (e.g. of a lost device) don't open it.
     */
    @Test
    public void resetVaultGetsNewKeys() throws Exception {
        LocalStorageProvider storage = new MemoryStorageProvider();
        byte[] exported;
        byte[] oldSalt;
        try (TestServer old = TestServer.start()) {
            VaultClient<OtpBlob> client = VaultClient.otp(old.getUrl(), storage, VaultKey.ofPassword(BACKUP_PASSWORD));
            create(client).add(account("A"));
            exported = client.exportKey();
            oldSalt = new DatabaseClient(old.getUrl(), AuthProtocol.TOTP_VAULT_PREFIX).getInstallSalt();
        }

        // the content of the local copy is kept
        OtpStore recreated = OtpStore.open(withPassword(storage));
        Assert.assertNotNull(recreated);
        Assert.assertEquals(recreated.getLocalReason(), ClientValue.LocalReason.NOT_ON_SERVER);
        recreated.add(account("B"));
        byte[] newSalt = new DatabaseClient(server.getUrl(), AuthProtocol.TOTP_VAULT_PREFIX).getInstallSalt();
        Assert.assertNotNull(newSalt);
        Assert.assertNotEquals(newSalt, oldSalt);
        OtpStore reopened = OtpStore.open(withPassword(new MemoryStorageProvider()));
        Assert.assertNotNull(reopened);
        Assert.assertEquals(issuers(reopened), List.of("A", "B"));

        Assert.expectThrows(WrongPasswordException.class, () -> OtpStore.open(VaultClient.otp(
                server.getUrl(), new MemoryStorageProvider(), VaultKey.ofExportedKey(exported))));
    }

    /**
     * After a failed load, nothing is saved with the state of an earlier one.
     */
    @Test
    public void noSaveAfterFailedLoad() throws Exception {
        VaultClient<OtpBlob> client = VaultClient.otp(server.getUrl(), new MemoryStorageProvider(),
                                                      VaultKey.ofExportedKey(new byte[VaultKey.EXPORTED_LENGTH]));
        Assert.expectThrows(WrongPasswordException.class, client::load);
        Assert.expectThrows(IllegalStateException.class, () -> client.save(new OtpBlob()));
    }

    /**
     * Only keys that the server accepted are exported: not those of a new vault before its first save, nor those of a
     * local copy while the server is unreachable.
     */
    @Test
    public void exportOnlyRegisteredKeys() throws Exception {
        LocalStorageProvider storage = new MemoryStorageProvider();
        VaultClient<OtpBlob> client = withPassword(storage);
        OtpStore store = create(client);
        Assert.expectThrows(IllegalStateException.class, client::exportKey);
        store.add(account("A"));
        client.exportKey();

        VaultClient<OtpBlob> offline =
                VaultClient.otp("http://127.0.0.1:1", storage, VaultKey.ofPassword(BACKUP_PASSWORD));
        Assert.assertNotNull(OtpStore.open(offline));
        Assert.expectThrows(IllegalStateException.class, offline::exportKey);

        // The server knows another vault (created again elsewhere, with another password), which refuses our keys: the
        // local copy is used, and nothing is exported.
        try (TestServer other = TestServer.start()) {
            create(VaultClient.otp(other.getUrl(), new MemoryStorageProvider(),
                                   VaultKey.ofPassword("other".getBytes(StandardCharsets.UTF_8)))).add(account("X"));
            VaultClient<OtpBlob> refused =
                    VaultClient.otp(other.getUrl(), storage, VaultKey.ofPassword(BACKUP_PASSWORD));
            OtpStore local = OtpStore.open(refused);
            Assert.assertNotNull(local);
            Assert.assertEquals(local.getLocalReason(), ClientValue.LocalReason.SERVER_UNAVAILABLE);
            Assert.expectThrows(IllegalStateException.class, refused::exportKey);
        }
    }

    /**
     * Only the password vault existed in the old format: a 2FA client never reads a legacy blob.
     */
    @Test
    public void legacyLocalCopyIsNotRead() throws Exception {
        LocalStorageProvider storage = new MemoryStorageProvider();
        try (var in = LegacyBlobTest.class.getResourceAsStream("jackson3-db.bin")) {
            storage.save(in.readAllBytes());
        }
        VaultClient<OtpBlob> client = VaultClient.otp("http://127.0.0.1:1", storage,
                                                       VaultKey.ofPassword(LegacyBlobTest.PASSWORD));
        Exception e = Assert.expectThrows(Exception.class, () -> OtpStore.open(client));
        Assert.assertTrue(e.getMessage().contains("unknown format"), e.getMessage());
    }

    @Test
    public void storeModifications() throws Exception {
        OtpStore store = create(withPassword(new MemoryStorageProvider()));
        OtpAccount a = account("A");
        OtpAccount b = account("B");
        store.addAll(List.of(a, b));
        Assert.expectThrows(IllegalArgumentException.class, () -> store.add(a));

        OtpAccount renamed = account("A2");
        renamed.setId(a.getId());
        store.update(renamed);
        store.delete(b.getId());
        Assert.assertEquals(issuers(store), List.of("A2"));
        Assert.expectThrows(IllegalStateException.class, () -> store.delete(b.getId()));

        OtpStore reopened = OtpStore.open(withPassword(new MemoryStorageProvider()));
        Assert.assertNotNull(reopened);
        Assert.assertEquals(reopened.getAccounts(), List.of(renamed));
    }

    @Test
    public void rejectsBadExportedKey() {
        Assert.expectThrows(IllegalArgumentException.class, () -> VaultKey.ofExportedKey(new byte[10]));
    }

    /**
     * The password vault's client is the same code: an unrelated type parameter can't sneak in.
     */
    @Test
    public void passwordClientIsAVaultClient() throws Exception {
        VaultClient<PasswordBlob> client =
                new PasswordClient(server.getUrl(), new MemoryStorageProvider(), BACKUP_PASSWORD);
        PasswordBlob blob = new PasswordBlob();
        PasswordEntry entry = new PasswordEntry();
        entry.setName("x");
        entry.setValue("y");
        blob.getPasswords().add(entry);
        client.load();
        client.save(blob);
        Assert.assertEquals(client.load().getValue(), blob);
    }
}
