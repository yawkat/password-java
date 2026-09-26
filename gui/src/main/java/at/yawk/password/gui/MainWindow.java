package at.yawk.password.gui;

import at.yawk.password.client.PasswordStore;
import at.yawk.password.model.PasswordEntry;
import io.qt.core.QModelIndex;
import io.qt.core.QSortFilterProxyModel;
import io.qt.core.Qt;
import io.qt.gui.QAction;
import io.qt.gui.QCloseEvent;
import io.qt.gui.QIcon;
import io.qt.gui.QKeySequence;
import io.qt.widgets.QLabel;
import io.qt.widgets.QMainWindow;
import io.qt.widgets.QMessageBox;
import io.qt.widgets.QSplitter;
import io.qt.widgets.QToolBar;
import io.qt.widgets.QVBoxLayout;
import io.qt.widgets.QWidget;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.Consumer;
import org.jetbrains.annotations.Nullable;

/**
 * @author yawkat
 */
public class MainWindow extends QMainWindow {
    private static final int STATUS_TIMEOUT_MS = 5000;

    private final PasswordStore store;
    private final Worker worker;
    private final ClipboardHelper clipboard;

    private final EntryListModel model = new EntryListModel(this);
    private final QSortFilterProxyModel proxy = new QSortFilterProxyModel(this);
    private final EntryListView listView = new EntryListView();
    private final SearchField searchField = new SearchField(listView);
    private final EntryEditor editor = new EntryEditor();
    private final QLabel offlineBanner = new QLabel(
            "Offline: showing the local copy, which may be outdated. Saving will overwrite the server copy.");

    private final QAction newAction = action("&New entry", "list-add", QKeySequence.StandardKey.New);
    private final QAction editAction = action("&Edit", "document-edit", "Ctrl+E", "F2");
    private final QAction deleteAction = action("&Delete", "edit-delete", "Del");
    private final QAction copyPasswordAction = action("&Copy password", "edit-copy", QKeySequence.StandardKey.Copy);
    private final QAction copyAllAction = action("Copy &all", "edit-copy", "Ctrl+Shift+C");
    private final QAction revealAction = action("&Reveal", "view-visible", "Ctrl+R");
    private final QAction reloadAction = action("Re&load", "view-refresh", QKeySequence.StandardKey.Refresh);
    private final QAction saveAction = action("&Save", "document-save", QKeySequence.StandardKey.Save);
    private final QAction cancelAction = action("Cancel editing", "dialog-cancel", "Esc");
    private final QAction findAction = action("&Find", "edit-find", QKeySequence.StandardKey.Find);

    private boolean busy;
    private boolean offlineSaveConfirmed;

    public MainWindow(PasswordStore store, Worker worker) {
        this.store = store;
        this.worker = worker;
        this.clipboard = new ClipboardHelper(this);

        setWindowTitle("Passwords");
        setWindowIcon(QIcon.fromTheme("dialog-password"));
        resize(900, 560);

        proxy.setSourceModel(model);
        proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive);
        proxy.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive);
        proxy.setSortLocaleAware(true);
        proxy.sort(0);
        listView.setModel(proxy);
        listView.setSearchField(searchField);
        listView.selectionModel().currentChanged.connect(this::onCurrentChanged);
        listView.entryActivated.connect(this::copyPassword);
        searchField.textChanged.connect(this::onSearchChanged);
        searchField.activated.connect(this::copyPassword);

        QWidget left = new QWidget();
        QVBoxLayout leftLayout = new QVBoxLayout(left);
        leftLayout.setContentsMargins(0, 0, 0, 0);
        leftLayout.addWidget(searchField);
        leftLayout.addWidget(listView);

        QSplitter splitter = new QSplitter(Qt.Orientation.Horizontal);
        splitter.addWidget(left);
        splitter.addWidget(editor);
        splitter.setStretchFactor(0, 1);
        splitter.setStretchFactor(1, 2);

        offlineBanner.setWordWrap(true);
        offlineBanner.setStyleSheet("background: #f67400; color: black; padding: 6px;");
        offlineBanner.setVisible(store.isFromLocalStorage());

        QWidget central = new QWidget();
        QVBoxLayout centralLayout = new QVBoxLayout(central);
        centralLayout.addWidget(offlineBanner);
        centralLayout.addWidget(splitter);
        setCentralWidget(central);

        copyPasswordAction.setToolTip("Copy the first line of the selected entry (Ctrl+C, Enter or double-click).\n" +
                                      "The clipboard is cleared after " + ClipboardHelper.CLEAR_AFTER_SECONDS +
                                      " seconds and when this application quits.");
        revealAction.setCheckable(true);

        QToolBar toolBar = addToolBar("Main");
        toolBar.setObjectName("mainToolBar");
        toolBar.setMovable(false);
        toolBar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon);
        toolBar.addAction(newAction);
        toolBar.addAction(editAction);
        toolBar.addAction(deleteAction);
        toolBar.addSeparator();
        toolBar.addAction(copyPasswordAction);
        toolBar.addAction(revealAction);
        toolBar.addSeparator();
        toolBar.addAction(reloadAction);
        // actions without toolbar buttons still need to be part of the window for their shortcuts
        addActions(List.of(copyAllAction, saveAction, cancelAction, findAction));

        newAction.triggered.connect(this::newEntry);
        editAction.triggered.connect(this::editEntry);
        deleteAction.triggered.connect(this::deleteEntry);
        copyPasswordAction.triggered.connect(this::copyPassword);
        copyAllAction.triggered.connect(this::copyAll);
        revealAction.toggled.connect(editor::setRevealed);
        reloadAction.triggered.connect(this::reload);
        saveAction.triggered.connect(this::save);
        cancelAction.triggered.connect(this::cancelEditing);
        findAction.triggered.connect(() -> {
            searchField.setFocus();
            searchField.selectAll();
        });
        editor.saveRequested.connect(this::save);
        editor.cancelRequested.connect(this::cancelEditing);

        showEntries(null);
        searchField.setFocus();
        statusBar().showMessage(store.getEntries().size() + " entries loaded", STATUS_TIMEOUT_MS);
    }

    private QAction action(String text, String icon, Object... shortcuts) {
        QAction action = new QAction(QIcon.fromTheme(icon), text, this);
        action.setShortcutContext(Qt.ShortcutContext.WindowShortcut);
        if (shortcuts.length == 1 && shortcuts[0] instanceof QKeySequence.StandardKey standardKey) {
            action.setShortcuts(standardKey);
        } else {
            action.setShortcuts(Arrays.stream(shortcuts).map(s -> new QKeySequence((String) s)).toList());
        }
        return action;
    }

    // ---- state ----

    /**
     * Replace the list contents with the current store entries and select the given entry, if still present.
     */
    private void showEntries(@Nullable PasswordEntry select) {
        model.setEntries(store.getEntries());
        offlineBanner.setVisible(store.isFromLocalStorage());
        select(select);
        updateActions();
    }

    private void select(@Nullable PasswordEntry entry) {
        int sourceRow = entry == null ? -1 : model.indexOf(entry);
        QModelIndex index = sourceRow == -1 ? null : proxy.mapFromSource(model.index(sourceRow, 0));
        if (index == null || !index.isValid()) {
            index = proxy.rowCount() > 0 ? proxy.index(0, 0) : null;
        }
        if (index != null) {
            listView.setCurrentIndex(index);
            listView.scrollTo(index);
        } else {
            listView.selectionModel().clearCurrentIndex();
        }
        editor.showEntry(selectedEntry());
        updateActions();
    }

    @Nullable
    private PasswordEntry selectedEntry() {
        QModelIndex index = listView.currentIndex();
        if (index == null || !index.isValid()) {
            return null;
        }
        return model.getEntry(proxy.mapToSource(index).row());
    }

    private void onCurrentChanged() {
        if (!editor.isEditing()) {
            editor.showEntry(selectedEntry());
        }
        updateActions();
    }

    private void onSearchChanged(String text) {
        PasswordEntry previous = selectedEntry();
        proxy.setFilterFixedString(text);
        select(previous);
    }

    private void updateActions() {
        boolean editing = editor.isEditing();
        boolean idle = !busy && !editing;
        boolean hasSelection = selectedEntry() != null;
        newAction.setEnabled(idle);
        editAction.setEnabled(idle && hasSelection);
        deleteAction.setEnabled(idle && hasSelection);
        copyPasswordAction.setEnabled(!editing && hasSelection);
        copyAllAction.setEnabled(!editing && hasSelection);
        revealAction.setEnabled(!editing);
        reloadAction.setEnabled(idle);
        saveAction.setEnabled(editing && !busy);
        cancelAction.setEnabled(editing && !busy);
        findAction.setEnabled(!editing);
        // entries can't be switched while editing, so there is no need to handle unsaved changes on selection change
        listView.setEnabled(!editing && !busy);
        searchField.setEnabled(!editing && !busy);
        editor.setEnabled(!busy);
    }

    // ---- actions ----

    private void copyPassword() {
        PasswordEntry entry = selectedEntry();
        if (entry == null || editor.isEditing()) {
            return;
        }
        clipboard.copySecret(PasswordStore.firstLine(entry.getValue()));
        statusBar().showMessage("Copied password of “" + entry.getName() + "” (cleared in " +
                                ClipboardHelper.CLEAR_AFTER_SECONDS + "s)", STATUS_TIMEOUT_MS);
    }

    private void copyAll() {
        PasswordEntry entry = selectedEntry();
        if (entry == null || editor.isEditing()) {
            return;
        }
        clipboard.copySecret(entry.getValue() == null ? "" : entry.getValue());
        statusBar().showMessage("Copied full entry “" + entry.getName() + "” (cleared in " +
                                ClipboardHelper.CLEAR_AFTER_SECONDS + "s)", STATUS_TIMEOUT_MS);
    }

    private void newEntry() {
        editor.startEditing(null);
        updateActions();
    }

    private void editEntry() {
        PasswordEntry entry = selectedEntry();
        if (entry != null) {
            editor.startEditing(entry);
            updateActions();
        }
    }

    private void cancelEditing() {
        if (!editor.isEditing() || busy) {
            return;
        }
        if (editor.isModified() && !confirmDiscard()) {
            return;
        }
        editor.showEntry(selectedEntry());
        updateActions();
        listView.setFocus();
    }

    private void save() {
        if (!editor.isEditing() || busy) {
            return;
        }
        String name = editor.getName();
        String value = editor.getValue();
        if (name.isEmpty()) {
            QMessageBox.warning(this, "Missing name", "The entry needs a name.");
            return;
        }
        if (!confirmOfflineSave()) {
            return;
        }
        PasswordEntry old = editor.getEntry();
        runModification(
                old == null ? "Created “" + name + "”" : "Saved “" + name + "”",
                () -> old == null ? store.add(name, value) : store.update(old, name, value),
                saved -> {
                    // clear the search if it would hide the saved entry
                    if (!name.toLowerCase().contains(searchField.text().toLowerCase())) {
                        searchField.clear();
                    }
                    editor.showEntry(null);
                    showEntries(saved);
                    listView.setFocus();
                });
    }

    private void deleteEntry() {
        PasswordEntry entry = selectedEntry();
        if (entry == null || busy || editor.isEditing()) {
            return;
        }
        QMessageBox.StandardButton answer = QMessageBox.question(
                this, "Delete entry", "Delete “" + entry.getName() + "”?",
                new QMessageBox.StandardButtons(QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No),
                QMessageBox.StandardButton.No);
        if (answer != QMessageBox.StandardButton.Yes || !confirmOfflineSave()) {
            return;
        }
        int row = listView.currentIndex().row();
        runModification("Deleted “" + entry.getName() + "”", () -> {
            store.delete(entry);
            return null;
        }, ignored -> {
            model.setEntries(store.getEntries());
            offlineBanner.setVisible(store.isFromLocalStorage());
            int newRow = Math.min(row, proxy.rowCount() - 1);
            select(newRow < 0 ? null : model.getEntry(proxy.mapToSource(proxy.index(newRow, 0)).row()));
        });
    }

    private void reload() {
        if (busy || editor.isEditing()) {
            return;
        }
        PasswordEntry previous = selectedEntry();
        String previousName = previous == null ? null : previous.getName();
        setBusy(true, "Reloading…");
        worker.run(() -> {
            store.reload();
            return null;
        }, ignored -> {
            setBusy(false, null);
            offlineSaveConfirmed = false;
            PasswordEntry match = store.getEntries().stream()
                    .filter(e -> e.getName().equals(previousName))
                    .findFirst().orElse(null);
            showEntries(match);
            statusBar().showMessage(store.isFromLocalStorage() ?
                                            "Server unreachable, loaded local copy" :
                                            "Reloaded " + store.getEntries().size() + " entries", STATUS_TIMEOUT_MS);
        }, e -> {
            setBusy(false, null);
            QMessageBox.critical(this, "Reload failed", "Could not reload the database:\n" + e.getMessage());
        });
    }

    private <T> void runModification(String successMessage, Callable<T> task, Consumer<T> onSuccess) {
        setBusy(true, "Saving…");
        worker.run(task, result -> {
            setBusy(false, null);
            onSuccess.accept(result);
            statusBar().showMessage(successMessage, STATUS_TIMEOUT_MS);
        }, e -> {
            setBusy(false, null);
            QMessageBox.critical(
                    this, "Save failed",
                    "The change could not be saved to the server:\n" + e.getMessage() +
                    "\n\nIt may have been written to the local backup only. Your change has been kept here, " +
                    "try again once the server is reachable.");
        });
    }

    private void setBusy(boolean busy, @Nullable String message) {
        this.busy = busy;
        if (message != null) {
            statusBar().showMessage(message);
        } else {
            statusBar().clearMessage();
        }
        updateActions();
    }

    private boolean confirmOfflineSave() {
        if (!store.isFromLocalStorage() || offlineSaveConfirmed) {
            return true;
        }
        QMessageBox.StandardButton answer = QMessageBox.warning(
                this, "Offline copy",
                "The database was loaded from the local copy because the server was unreachable. It may be " +
                "older than the copy on the server.\n\nSaving replaces the server copy with this version. Continue?",
                new QMessageBox.StandardButtons(QMessageBox.StandardButton.Save, QMessageBox.StandardButton.Cancel),
                QMessageBox.StandardButton.Cancel);
        offlineSaveConfirmed = answer == QMessageBox.StandardButton.Save;
        return offlineSaveConfirmed;
    }

    private boolean confirmDiscard() {
        QMessageBox.StandardButton answer = QMessageBox.question(
                this, "Unsaved changes", "Discard the changes to this entry?",
                new QMessageBox.StandardButtons(QMessageBox.StandardButton.Discard, QMessageBox.StandardButton.Cancel),
                QMessageBox.StandardButton.Cancel);
        return answer == QMessageBox.StandardButton.Discard;
    }

    @Override
    protected void closeEvent(QCloseEvent event) {
        if (busy) {
            statusBar().showMessage("Please wait until saving has finished", STATUS_TIMEOUT_MS);
            event.ignore();
            return;
        }
        if (editor.isModified() && !confirmDiscard()) {
            event.ignore();
            return;
        }
        clipboard.clearIfOurs();
        event.accept();
    }
}
