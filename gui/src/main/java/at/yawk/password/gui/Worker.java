package at.yawk.password.gui;

import io.qt.core.QObject;
import io.qt.core.Qt;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;

/**
 * Runs blocking client operations (scrypt, network) off the UI thread and delivers the results back on the UI
 * thread. Tasks run sequentially.
 *
 * @author yawkat
 */
@Slf4j
public class Worker extends QObject {
    public final Signal1<Runnable> dispatch = new Signal1<>();

    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "password-worker");
        thread.setDaemon(true);
        return thread;
    });

    /**
     * Must be created on the UI thread.
     */
    public Worker() {
        dispatch.connect(this::runOnUiThread, Qt.ConnectionType.QueuedConnection);
    }

    public void runOnUiThread(Runnable runnable) {
        runnable.run();
    }

    <T> void run(Callable<T> task, Consumer<T> onSuccess, Consumer<Exception> onError) {
        executor.execute(() -> {
            Runnable callback;
            try {
                T result = task.call();
                callback = () -> onSuccess.accept(result);
            } catch (Exception e) {
                log.warn("Background task failed", e);
                callback = () -> onError.accept(e);
            }
            dispatch.emit(callback);
        });
    }
}
