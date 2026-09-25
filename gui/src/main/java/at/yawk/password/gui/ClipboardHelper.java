package at.yawk.password.gui;

import io.qt.core.QMimeData;
import io.qt.core.QObject;
import io.qt.core.QTimer;
import io.qt.gui.QClipboard;
import io.qt.gui.QGuiApplication;
import java.nio.charset.StandardCharsets;
import org.jetbrains.annotations.Nullable;

/**
 * Copies secrets to the clipboard and removes them again after a timeout.
 *
 * @author yawkat
 */
class ClipboardHelper {
    static final int CLEAR_AFTER_SECONDS = 30;

    /**
     * Tells KDE Klipper (and other clipboard managers honoring it) not to keep the entry in its history.
     */
    private static final String PASSWORD_MANAGER_HINT = "x-kde-passwordManagerHint";

    private final QTimer clearTimer;
    @Nullable private String copiedSecret;

    ClipboardHelper(QObject parent) {
        clearTimer = new QTimer(parent);
        clearTimer.setSingleShot(true);
        clearTimer.setInterval(CLEAR_AFTER_SECONDS * 1000);
        clearTimer.timeout.connect(this::clearIfOurs);
    }

    void copySecret(String text) {
        QMimeData mimeData = new QMimeData();
        mimeData.setText(text);
        mimeData.setData(PASSWORD_MANAGER_HINT, "secret".getBytes(StandardCharsets.US_ASCII));
        QGuiApplication.clipboard().setMimeData(mimeData);
        copiedSecret = text;
        clearTimer.start();
    }

    /**
     * Clear the clipboard if it still contains the secret we put there.
     */
    void clearIfOurs() {
        if (copiedSecret == null) {
            return;
        }
        QClipboard clipboard = QGuiApplication.clipboard();
        QMimeData current = clipboard.mimeData();
        // ownsClipboard() is not implemented by every platform plugin, so compare the contents instead
        if (current != null && current.hasFormat(PASSWORD_MANAGER_HINT) && copiedSecret.equals(current.text())) {
            clipboard.clear();
        }
        copiedSecret = null;
    }
}
