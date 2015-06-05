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
}
