package at.yawk.password.android

import android.os.SystemClock
import androidx.credentials.provider.CallingAppInfo
import at.yawk.password.model.Passkey

/**
 * The passkeys of a database that the user just unlocked for a sign-in, between the two steps of Android's credential
 * manager: the unlock returns the list of passkeys to choose from, and the chosen one is used by a new activity.
 *
 * Only the passkeys offered for that request are kept, for the app and origin that asked ([key]): the unlock counts
 * as user verification for that sign-in, not for others. Kept in memory for [TTL_MS] at most, and only for one
 * sign-in: [take] forgets them, and so does any change of the database's passkeys ([clear]).
 */
object PasskeySession {
    private const val TTL_MS = 2 * 60 * 1000L

    private var passkeys: List<Passkey>? = null
    private var caller: String? = null
    private var expires = 0L

    /**
     * Who asks: the calling app and the origin it asks for, e.g. a browser and a website
     */
    fun key(info: CallingAppInfo, caller: PasskeyCaller): String = info.packageName + " " + caller.origin

    /**
     * Keep [passkeys], the passkeys offered to [caller] ([key]).
     */
    @Synchronized
    fun put(passkeys: List<Passkey>, caller: String) {
        this.passkeys = passkeys
        this.caller = caller
        expires = SystemClock.elapsedRealtime() + TTL_MS
    }

    /**
     * The passkeys offered to [caller], or `null` if there are none or they expired.
     */
    @Synchronized
    fun get(caller: String): List<Passkey>? {
        if (SystemClock.elapsedRealtime() >= expires) {
            clear()
        }
        return if (caller == this.caller) passkeys else null
    }

    /**
     * The passkey with [id] offered to [caller], and forget all.
     */
    @Synchronized
    fun take(id: String, caller: String): Passkey? {
        val passkey = get(caller)?.firstOrNull { it.id == id }
        clear()
        return passkey
    }

    @Synchronized
    fun clear() {
        passkeys = null
        caller = null
        expires = 0
    }
}
