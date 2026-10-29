package at.yawk.password.app.fido

import at.yawk.password.app.PasskeyOutcome
import at.yawk.password.app.PasskeyRequest
import at.yawk.password.model.Passkey
import java.io.Closeable
import java.io.IOException
import java.nio.channels.ClosedChannelException
import java.nio.file.Path
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(SecurityKey::class.java)

/**
 * The passkeys of the password database as a USB security key that browsers can use: a virtual HID device ([Uhid])
 * speaking CTAPHID ([CtapHid]) and CTAP2 ([Ctap2]). Linux only.
 */
class SecurityKey private constructor(private val uhid: Uhid, ctap2: Ctap2) : Closeable {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val hid = CtapHid(uhid::sendInput, scope, ctap2::process)
    private val reader = Thread(::readLoop, "security-key").apply { isDaemon = true }

    private fun readLoop() {
        try {
            while (true) {
                when (val event = uhid.read()) {
                    is Uhid.Event.Output -> hid.onReport(event.data)
                    is Uhid.Event.GetReport -> uhid.replyGetReport(event.id)
                    is Uhid.Event.SetReport -> uhid.replySetReport(event.id)
                    is Uhid.Event.Other -> log.debug("uhid event {}", event.type)
                }
            }
        } catch (e: ClosedChannelException) {
            // closed
        } catch (e: IOException) {
            log.warn("The security key failed", e)
        }
    }

    override fun close() {
        scope.cancel()
        uhid.close()
    }

    companion object {
        /**
         * Create the device and start answering it.
         *
         * @throws IOException if the device can't be created, e.g. without access to `/dev/uhid`
         */
        fun start(
            handler: suspend (PasskeyRequest) -> PasskeyOutcome,
            unlockedPasskeys: () -> List<Passkey>?,
            path: Path = Path.of(Uhid.DEFAULT_PATH),
        ): SecurityKey {
            val uhid = Uhid.createSecurityKey("password-java security key", path)
            val key = SecurityKey(uhid, Ctap2(handler, unlockedPasskeys))
            key.reader.start()
            log.info("Security key created")
            return key
        }
    }
}
