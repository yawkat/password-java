package at.yawk.password.gui;

import io.qt.core.QCoreApplication;
import io.qt.core.Qt;
import io.qt.gui.QKeyEvent;
import io.qt.widgets.QAbstractItemView;
import io.qt.widgets.QListView;
import io.qt.widgets.QWidget;

/**
 * Entry list. Enter emits {@link #entryActivated} (the {@code activated} signal of item views would also fire on single
 * click under KDE), and typing starts a search.
 *
 * @author yawkat
 */
public class EntryListView extends QListView {
    public final Signal0 entryActivated = new Signal0();

    private QWidget searchField;

    public EntryListView() {
        setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection);
        setUniformItemSizes(true);
        doubleClicked.connect(entryActivated);
    }

    void setSearchField(QWidget searchField) {
        this.searchField = searchField;
    }

    @Override
    protected void keyPressEvent(QKeyEvent event) {
        int key = event.key();
        boolean commandModifier = event.modifiers().testFlag(Qt.KeyboardModifier.ControlModifier) ||
                                 event.modifiers().testFlag(Qt.KeyboardModifier.AltModifier) ||
                                 event.modifiers().testFlag(Qt.KeyboardModifier.MetaModifier);
        if (key == Qt.Key.Key_Return.value() || key == Qt.Key.Key_Enter.value()) {
            entryActivated.emit();
        } else if (!commandModifier && searchField != null && !event.text().isEmpty() &&
                   !Character.isISOControl(event.text().charAt(0))) {
            searchField.setFocus();
            QCoreApplication.sendEvent(searchField, event);
        } else {
            super.keyPressEvent(event);
        }
    }
}
