package at.yawk.password.android;

import android.os.Build;
import java.lang.reflect.RecordComponent;

/**
 * Java 17 methods that Android only has since API 34, for Jackson 3. The build rewrites Jackson's calls of these
 * methods into calls of this class (see {@code Java17ApiBackport} in build-logic).
 *
 * <p>Before API 34, Android has no records or sealed classes: D8 compiles records into ordinary classes, and none of
 * the classes (de)serialized here is one.
 */
@SuppressWarnings({"unused", "NewApi"})
public final class Java17Compat {
    private static final boolean JAVA_17 = Build.VERSION.SDK_INT >= 34;

    private Java17Compat() {}

    public static boolean isRecord(Class<?> cls) {
        return JAVA_17 && cls.isRecord();
    }

    public static RecordComponent[] getRecordComponents(Class<?> cls) {
        return JAVA_17 ? cls.getRecordComponents() : null;
    }

    public static boolean isSealed(Class<?> cls) {
        return JAVA_17 && cls.isSealed();
    }

    public static Class<?>[] getPermittedSubclasses(Class<?> cls) {
        return JAVA_17 ? cls.getPermittedSubclasses() : null;
    }

    public static String formatted(String format, Object... args) {
        return String.format(format, args);
    }
}
