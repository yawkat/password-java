package at.yawk.password.gui;

import io.qt.core.QCoreApplication;
import io.qt.core.QEvent;
import io.qt.core.Qt;
import io.qt.gui.QKeyEvent;
import io.qt.gui.QKeySequence;
import io.qt.widgets.QLineEdit;
import io.qt.widgets.QWidget;

/**
 * Search box above the entry list. Navigation keys are forwarded to the list, and the window-wide copy shortcut
 * keeps working while the search box has focus as long as no search text is selected.
 *
 * @author yawkat
 */
public class SearchField extends QLineEdit {
    public final Signal0 activated = new Signal0();

    private final QWidget list;

    public SearchField(QWidget list) {
        this.list = list;
        setPlaceholderText("Search (Ctrl+F)");
        setClearButtonEnabled(true);
    }

    @Override
    public boolean event(QEvent event) {
        if (event.type() == QEvent.Type.ShortcutOverride &&
            event instanceof QKeyEvent keyEvent &&
            keyEvent.matches(QKeySequence.StandardKey.Copy) &&
            !hasSelectedText()) {
            // don't claim Ctrl+C, let the window copy the selected password
            event.ignore();
            return false;
        }
        return super.event(event);
    }

    @Override
    protected void keyPressEvent(QKeyEvent event) {
        int key = event.key();
        if (key == Qt.Key.Key_Up.value() || key == Qt.Key.Key_Down.value() ||
            key == Qt.Key.Key_PageUp.value() || key == Qt.Key.Key_PageDown.value()) {
            QCoreApplication.sendEvent(list, event);
        } else if (key == Qt.Key.Key_Return.value() || key == Qt.Key.Key_Enter.value()) {
            activated.emit();
        } else if (key == Qt.Key.Key_Escape.value() && !text().isEmpty()) {
            clear();
        } else {
            super.keyPressEvent(event);
        }
    }
}
