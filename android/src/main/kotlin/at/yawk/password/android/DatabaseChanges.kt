package at.yawk.password.android

import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow

/**
 * Tells [MainActivity] that [PasskeyActivity] saved the password database through its own client. Each has its own
 * copy, and the server keeps whichever was saved last, so the main activity must reload before it saves again.
 */
object DatabaseChanges {
    private val changes =
        MutableSharedFlow<Unit>(extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST)

    val flow: SharedFlow<Unit> get() = changes

    fun changed() {
        changes.tryEmit(Unit)
    }
}
