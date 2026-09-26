package at.yawk.password.gui;

import at.yawk.password.MultiFileLocalStorageProvider;
import at.yawk.password.client.PasswordClient;
import at.yawk.password.client.PasswordStore;
import io.qt.core.Qt;
import io.qt.widgets.QDialog;
import io.qt.widgets.QDialogButtonBox;
import io.qt.widgets.QFormLayout;
import io.qt.widgets.QInputDialog;
import io.qt.widgets.QLabel;
import io.qt.widgets.QLineEdit;
import io.qt.widgets.QMessageBox;
import io.qt.widgets.QProgressBar;
import io.qt.widgets.QVBoxLayout;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;
import org.jetbrains.annotations.Nullable;

/**
 * Asks for the master password and loads the database.
 *
 * @author yawkat
 */
public class UnlockDialog extends QDialog {
    private final GuiConfig config;
    private final Worker worker;

    private final QLineEdit passwordEdit = new QLineEdit();
    private final QLabel errorLabel = new QLabel();
    private final QProgressBar progress = new QProgressBar();
    private final QDialogButtonBox buttons = new QDialogButtonBox();

    @Nullable private PasswordStore store;

    public UnlockDialog(GuiConfig config, Worker worker) {
        this.config = config;
        this.worker = worker;
        setWindowTitle("Unlock password database");

        passwordEdit.setEchoMode(QLineEdit.EchoMode.Password);
        errorLabel.setWordWrap(true);
        errorLabel.setStyleSheet("color: #da4453;");
        errorLabel.setVisible(false);
        progress.setRange(0, 0);
        progress.setTextVisible(false);
        progress.setVisible(false);

        buttons.addButton("&Unlock", QDialogButtonBox.ButtonRole.AcceptRole);
        buttons.addButton(QDialogButtonBox.StandardButton.Close);
        buttons.accepted.connect(this::unlock);
        buttons.rejected.connect(this::reject);

        QFormLayout form = new QFormLayout();
        QLabel server = new QLabel(config.getUrl());
        server.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse);
        form.addRow("Server:", server);
        form.addRow("&Master password:", passwordEdit);

        QVBoxLayout layout = new QVBoxLayout(this);
        layout.addLayout(form);
        layout.addWidget(errorLabel);
        layout.addWidget(progress);
        layout.addWidget(buttons);
        setMinimumWidth(420);
    }

    @Nullable
    PasswordStore getStore() {
        return store;
    }

    private void unlock() {
        String password = passwordEdit.text();
        if (password.isEmpty()) {
            return;
        }
        setBusy(true);
        File storageDirectory = config.getStorageDirectory();
        record Loaded(PasswordClient client, @Nullable PasswordStore store) {}
        worker.run(() -> {
            if (!storageDirectory.isDirectory()) {
                Files.createDirectories(storageDirectory.toPath(),
                                        PosixFilePermissions.asFileAttribute(
                                                PosixFilePermissions.fromString("rwx------")));
            }
            PasswordClient client = new PasswordClient(
                    config.getUrl(),
                    new MultiFileLocalStorageProvider(storageDirectory),
                    password.getBytes(StandardCharsets.UTF_8));
            return new Loaded(client, PasswordStore.open(client));
        }, loaded -> {
            if (loaded.store() != null) {
                store = loaded.store();
                accept();
            } else if (confirmNewDatabase(password)) {
                store = PasswordStore.createEmpty(loaded.client());
                accept();
            } else {
                setBusy(false);
            }
        }, e -> {
            setBusy(false);
            String message = e.getMessage() == null ? e.toString() : e.getMessage();
            if (message.startsWith("Invalid HMAC")) {
                showError("Wrong password.");
            } else if (message.contains("response code: 403")) {
                showError("The server rejected the password, and no local copy could be opened.");
            } else {
                showError("Could not load the database: " + message);
            }
            passwordEdit.selectAll();
            passwordEdit.setFocus();
        });
    }

    private boolean confirmNewDatabase(String password) {
        QMessageBox.StandardButton answer = QMessageBox.question(
                this, "No database found",
                "No password database exists on the server or in " + config.getStorageDirectory() +
                ".\n\nCreate a new, empty database with this master password?",
                new QMessageBox.StandardButtons(QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No),
                QMessageBox.StandardButton.No);
        if (answer != QMessageBox.StandardButton.Yes) {
            return false;
        }
        String repeated = QInputDialog.getText(
                this, "Confirm master password", "Repeat the master password:", QLineEdit.EchoMode.Password);
        if (repeated == null) {
            return false;
        }
        if (!repeated.equals(password)) {
            showError("The passwords do not match.");
            return false;
        }
        return true;
    }

    private void setBusy(boolean busy) {
        passwordEdit.setEnabled(!busy);
        buttons.setEnabled(!busy);
        progress.setVisible(busy);
        if (busy) {
            errorLabel.setVisible(false);
        }
    }

    private void showError(String message) {
        errorLabel.setText(message);
        errorLabel.setVisible(true);
    }
}
