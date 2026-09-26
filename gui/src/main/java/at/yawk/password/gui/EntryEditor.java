package at.yawk.password.gui;

import at.yawk.password.client.PasswordStore;
import at.yawk.password.model.PasswordEntry;
import io.qt.gui.QFontDatabase;
import io.qt.gui.QIcon;
import io.qt.widgets.QFormLayout;
import io.qt.widgets.QHBoxLayout;
import io.qt.widgets.QLabel;
import io.qt.widgets.QLineEdit;
import io.qt.widgets.QPlainTextEdit;
import io.qt.widgets.QPushButton;
import io.qt.widgets.QVBoxLayout;
import io.qt.widgets.QWidget;
import java.security.SecureRandom;
import java.util.Objects;
import org.jetbrains.annotations.Nullable;

/**
 * Detail pane showing a single entry. In view mode the first line (the password) is masked unless revealed; in edit
 * mode name and value are editable.
 *
 * @author yawkat
 */
public class EntryEditor extends QWidget {
    private static final String MASK = "••••••••••••";
    private static final String GENERATOR_ALPHABET =
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!@#%+=";
    private static final int GENERATED_LENGTH = 24;

    public final Signal0 saveRequested = new Signal0();
    public final Signal0 cancelRequested = new Signal0();

    private final SecureRandom random = new SecureRandom();

    private final QLabel placeholder = new QLabel("Select an entry, or press Ctrl+N to create one.");
    private final QWidget form = new QWidget();
    private final QLineEdit nameEdit = new QLineEdit();
    private final QPlainTextEdit valueEdit = new QPlainTextEdit();
    private final QWidget editButtons = new QWidget();

    @Nullable private PasswordEntry entry;
    private boolean editing;
    private boolean revealed;

    public EntryEditor() {
        nameEdit.setPlaceholderText("Name");
        valueEdit.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont));
        valueEdit.setPlaceholderText("First line: password\nFurther lines: username, notes, …");
        valueEdit.setTabChangesFocus(true);

        QPushButton generate = new QPushButton(QIcon.fromTheme("roll"), "Generate password");
        generate.setToolTip("Replace the first line with a random password");
        generate.clicked.connect(this::generatePassword);
        QPushButton cancel = new QPushButton(QIcon.fromTheme("dialog-cancel"), "Cancel");
        cancel.clicked.connect(cancelRequested);
        QPushButton save = new QPushButton(QIcon.fromTheme("document-save"), "Save");
        save.setDefault(true);
        save.clicked.connect(saveRequested);

        QHBoxLayout buttonLayout = new QHBoxLayout(editButtons);
        buttonLayout.setContentsMargins(0, 0, 0, 0);
        buttonLayout.addWidget(generate);
        buttonLayout.addStretch();
        buttonLayout.addWidget(cancel);
        buttonLayout.addWidget(save);

        QFormLayout formLayout = new QFormLayout(form);
        formLayout.setContentsMargins(0, 0, 0, 0);
        formLayout.addRow("&Name:", nameEdit);
        formLayout.addRow("&Value:", valueEdit);
        formLayout.addRow(editButtons);

        placeholder.setWordWrap(true);
        QVBoxLayout layout = new QVBoxLayout(this);
        layout.addWidget(placeholder);
        layout.addWidget(form);

        showEntry(null);
    }

    void showEntry(@Nullable PasswordEntry entry) {
        this.entry = entry;
        editing = false;
        placeholder.setVisible(entry == null);
        form.setVisible(entry != null);
        editButtons.setVisible(false);
        nameEdit.setReadOnly(true);
        valueEdit.setReadOnly(true);
        updateContents();
    }

    /**
     * @param entry The entry to edit, or {@code null} to create a new one.
     */
    void startEditing(@Nullable PasswordEntry entry) {
        this.entry = entry;
        editing = true;
        placeholder.setVisible(false);
        form.setVisible(true);
        editButtons.setVisible(true);
        nameEdit.setReadOnly(false);
        valueEdit.setReadOnly(false);
        updateContents();
        nameEdit.setFocus();
        if (entry != null) {
            nameEdit.selectAll();
        }
    }

    void setRevealed(boolean revealed) {
        this.revealed = revealed;
        if (!editing) {
            updateContents();
        }
    }

    private void updateContents() {
        if (entry == null) {
            nameEdit.setText("");
            valueEdit.setPlainText("");
            return;
        }
        nameEdit.setText(entry.getName());
        String value = Objects.requireNonNullElse(entry.getValue(), "");
        if (editing || revealed) {
            valueEdit.setPlainText(value);
        } else {
            valueEdit.setPlainText(MASK + value.substring(PasswordStore.firstLine(value).length()));
        }
    }

    private void generatePassword() {
        StringBuilder password = new StringBuilder(GENERATED_LENGTH);
        for (int i = 0; i < GENERATED_LENGTH; i++) {
            password.append(GENERATOR_ALPHABET.charAt(random.nextInt(GENERATOR_ALPHABET.length())));
        }
        String value = valueEdit.toPlainText();
        valueEdit.setPlainText(password + value.substring(PasswordStore.firstLine(value).length()));
    }

    boolean isEditing() {
        return editing;
    }

    /**
     * @return The entry being shown or edited, {@code null} if nothing is shown or a new entry is being created.
     */
    @Nullable
    PasswordEntry getEntry() {
        return entry;
    }

    boolean isModified() {
        if (!editing) {
            return false;
        }
        if (entry == null) {
            return !getName().isEmpty() || !getValue().isEmpty();
        }
        return !getName().equals(entry.getName()) ||
               !getValue().equals(Objects.requireNonNullElse(entry.getValue(), ""));
    }

    String getName() {
        return nameEdit.text().strip();
    }

    String getValue() {
        return valueEdit.toPlainText();
    }
}
