package at.yawk.password.android

import android.os.SystemClock
import at.yawk.password.model.Passkey

/**
 * The passkeys of a database that the user just unlocked for a sign-in, between the two steps of Android's credential
 * manager: the unlock returns the list of passkeys to choose from, and the chosen one is used by a new activity.
 *
 * Only the passkeys offered for that request are kept, for the app that asked: the unlock counts as user verification
 * for that sign-in, not for others. Kept in memory for [TTL_MS] at most, and only for one sign-in: [take] forgets them.
 */
object PasskeySession {
    private const val TTL_MS = 2 * 60 * 1000L

    private var passkeys: List<Passkey>? = null
    private var packageName: String? = null
    private var expires = 0L

    /**
     * Keep [passkeys], the passkeys offered to the app [packageName].
     */
    @Synchronized
    fun put(passkeys: List<Passkey>, packageName: String) {
        this.passkeys = passkeys
        this.packageName = packageName
        expires = SystemClock.elapsedRealtime() + TTL_MS
    }

    /**
     * The passkeys offered to [packageName], or `null` if there are none or they expired.
     */
    @Synchronized
    fun get(packageName: String): List<Passkey>? {
        if (SystemClock.elapsedRealtime() >= expires) {
            clear()
        }
        return if (packageName == this.packageName) passkeys else null
    }

    /**
     * The passkey with [id] offered to [packageName], and forget all.
     */
    @Synchronized
    fun take(id: String, packageName: String): Passkey? {
        val passkey = get(packageName)?.firstOrNull { it.id == id }
        clear()
        return passkey
    }

    @Synchronized
    fun clear() {
        passkeys = null
        packageName = null
        expires = 0
    }
}
