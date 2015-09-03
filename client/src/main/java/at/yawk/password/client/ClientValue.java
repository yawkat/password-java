package at.yawk.password.client;

import javax.annotation.Nullable;
import lombok.Value;

/**
 * @author yawkat
 */
@Value
public class ClientValue<T> {
    @Nullable private final T value;
    private final boolean fromLocalStorage;

    public <R, E extends Throwable> ClientValue<R> map(ThrowingFunction<T, R, E> function) throws E {
        return new ClientValue<>(value == null ? null : function.apply(value), fromLocalStorage);
    }

    public interface ThrowingFunction<T, R, E extends Throwable> {
        R apply(T obj) throws E;
    }
}
