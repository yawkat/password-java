package at.yawk.password.gui;

import io.qt.widgets.QApplication;
import io.qt.widgets.QDialog;
import io.qt.widgets.QMessageBox;
import lombok.extern.slf4j.Slf4j;

/**
 * @author yawkat
 */
@Slf4j
public class PasswordGui {
    public static void main(String[] args) {
        QApplication.initialize(args);
        QApplication.setApplicationName("password-gui");
        QApplication.setApplicationDisplayName("Passwords");
        QApplication.setDesktopFileName("at.yawk.password");
        log.info("platform: {} (XDG_SESSION_TYPE={}, WAYLAND_DISPLAY={}, QT_QPA_PLATFORM={})",
                 QApplication.platformName(), System.getenv("XDG_SESSION_TYPE"), System.getenv("WAYLAND_DISPLAY"),
                 System.getenv("QT_QPA_PLATFORM"));

        try {
            GuiConfig config;
            try {
                config = GuiConfig.load();
            } catch (Exception e) {
                QMessageBox.critical(null, "Configuration error", "Could not read configuration: " + e);
                return;
            }

            Worker worker = new Worker();
            UnlockDialog unlockDialog = new UnlockDialog(config, worker);
            if (unlockDialog.exec() != QDialog.DialogCode.Accepted.value() || unlockDialog.getStore() == null) {
                return;
            }
            MainWindow window = new MainWindow(unlockDialog.getStore(), worker);
            unlockDialog.dispose();
            window.show();
            QApplication.exec();
        } finally {
            QApplication.shutdown();
        }
    }
}
