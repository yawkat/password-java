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
 * The passkeys of the password database as a USB security key that browsers can use: a virtual HID device
 * ([UhidHelper]) speaking CTAPHID ([CtapHid]) and CTAP2 ([Ctap2]). Linux only.
 */
class SecurityKey private constructor(
    private val device: UhidHelper,
    ctap2: Ctap2,
    private val onFailure: (IOException) -> Unit,
) : Closeable {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val hid = CtapHid(device::sendInput, scope, ctap2::process)
    private val reader = Thread(::readLoop, "security-key").apply { isDaemon = true }

    private fun readLoop() {
        try {
            while (true) {
                hid.onReport(device.read())
            }
        } catch (e: ClosedChannelException) {
            // closed
        } catch (e: IOException) {
            log.warn("The security key failed", e)
            onFailure(e)
        }
    }

    override fun close() {
        scope.cancel()
        device.close()
    }

    companion object {
        /**
         * Create the device and start answering it. If it fails later, e.g. because the helper ended, it calls
         * [onFailure] (on its own thread), and the device is gone.
         *
         * @throws IOException if the device can't be created, e.g. without the `password-uhid` helper
         */
        fun start(
            handler: suspend (PasskeyRequest) -> PasskeyOutcome,
            unlockedPasskeys: () -> List<Passkey>?,
            helperSocket: Path = Path.of(UhidHelper.SOCKET),
            onFailure: (IOException) -> Unit,
        ): SecurityKey {
            val key = SecurityKey(UhidHelper.connect(helperSocket), Ctap2(handler, unlockedPasskeys), onFailure)
            key.reader.start()
            log.info("Security key created")
            return key
        }
    }
}
