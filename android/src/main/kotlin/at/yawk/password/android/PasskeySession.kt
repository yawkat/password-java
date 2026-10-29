package at.yawk.password.android

import android.os.SystemClock
import at.yawk.password.model.Passkey

/**
 * The passkeys of a database that the user just unlocked for a sign-in, between the two steps of Android's credential
 * manager: the unlock returns the list of passkeys to choose from, and the chosen one is used by a new activity.
 *
 * Kept in memory for [TTL_MS] at most, and only for one sign-in: [take] forgets them.
 */
object PasskeySession {
    private const val TTL_MS = 2 * 60 * 1000L

    private var passkeys: List<Passkey>? = null
    private var expires = 0L

    @Synchronized
    fun put(passkeys: List<Passkey>) {
        this.passkeys = passkeys
        expires = SystemClock.elapsedRealtime() + TTL_MS
    }

    /**
     * The passkeys, or `null` if there are none or they expired.
     */
    @Synchronized
    fun get(): List<Passkey>? {
        if (SystemClock.elapsedRealtime() >= expires) {
            clear()
        }
        return passkeys
    }

    /**
     * The passkey with [id], and forget all.
     */
    @Synchronized
    fun take(id: String): Passkey? {
        val passkey = get()?.firstOrNull { it.id == id }
        clear()
        return passkey
    }

    @Synchronized
    fun clear() {
        passkeys = null
        expires = 0
    }
}
