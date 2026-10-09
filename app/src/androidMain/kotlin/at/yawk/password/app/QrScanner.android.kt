package at.yawk.password.app

import android.Manifest
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.LifecycleOwner
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

@Composable
actual fun qrScannerAvailable(): Boolean =
    LocalContext.current.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)

@Composable
actual fun QrScanner(onResult: (String) -> Unit, onError: (String) -> Unit, modifier: Modifier) {
    val context = LocalContext.current
    val currentOnError by rememberUpdatedState(onError)
    var permitted by remember {
        mutableStateOf(context.checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    val request = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) permitted = true else currentOnError("Scanning needs the camera permission.")
    }
    LaunchedEffect(Unit) {
        if (!permitted) request.launch(Manifest.permission.CAMERA)
    }
    if (permitted) {
        CameraPreview(onResult, onError, modifier)
    } else {
        Box(modifier, contentAlignment = Alignment.Center) {
            Text("Waiting for the camera permission…", Modifier.padding(16.dp), style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun CameraPreview(onResult: (String) -> Unit, onError: (String) -> Unit, modifier: Modifier) {
    val context = LocalContext.current
    val lifecycleOwner = remember(context) { context.lifecycleOwner() }
    val currentOnResult by rememberUpdatedState(onResult)
    val currentOnError by rememberUpdatedState(onError)
    val previewView = remember { PreviewView(context) }
    DisposableEffect(lifecycleOwner) {
        val analysisExecutor = Executors.newSingleThreadExecutor()
        val done = AtomicBoolean(false)
        val providerFuture = ProcessCameraProvider.getInstance(context)
        providerFuture.addListener({
            if (done.get()) return@addListener
            try {
                val provider = providerFuture.get()
                val preview = Preview.Builder().build().also { it.surfaceProvider = previewView.surfaceProvider }
                val analysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                val reader = MultiFormatReader().apply {
                    setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)))
                }
                analysis.setAnalyzer(analysisExecutor) { image ->
                    val text = image.use { decode(reader, it) }
                    if (text != null && done.compareAndSet(false, true)) {
                        context.mainExecutor.execute { currentOnResult(text) }
                    }
                }
                provider.unbindAll()
                provider.bindToLifecycle(lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            } catch (e: Exception) {
                // the camera's message, not the content of a code
                if (done.compareAndSet(false, true)) currentOnError("Could not open the camera: ${e.message ?: e}")
            }
        }, context.mainExecutor)
        onDispose {
            done.set(true)
            // unbind before stopping the analyzer's executor, which the camera would otherwise still feed
            val unbind = {
                runCatching { providerFuture.get().unbindAll() }
                analysisExecutor.shutdown()
            }
            if (providerFuture.isDone) unbind() else providerFuture.addListener(unbind, context.mainExecutor)
        }
    }
    AndroidView(factory = { previewView }, modifier = modifier)
}

/**
 * The text of a QR code in the frame, from its luminance (Y) plane, or `null` if there is none.
 */
private fun decode(reader: MultiFormatReader, image: ImageProxy): String? {
    val plane = image.planes[0]
    val buffer = plane.buffer
    val data = ByteArray(buffer.remaining())
    buffer.get(data)
    return decodeLuminance(reader, data, plane.rowStride, image.width, image.height)
}

/**
 * The text of a QR code in a luminance image whose rows are [rowStride] bytes apart (at least [width]: camera frames
 * may pad their rows, except the last one), or `null` if there is none.
 */
internal fun decodeLuminance(
    reader: MultiFormatReader,
    data: ByteArray,
    rowStride: Int,
    width: Int,
    height: Int,
): String? {
    // only reads the first width bytes of each row
    val source = PlanarYUVLuminanceSource(data, rowStride, height, 0, 0, width, height, false)
    return try {
        reader.decodeWithState(BinaryBitmap(HybridBinarizer(source))).text
    } catch (e: NotFoundException) {
        null
    } catch (e: ReaderException) {
        null
    } finally {
        reader.reset()
    }
}

private tailrec fun Context.lifecycleOwner(): LifecycleOwner = when (this) {
    is LifecycleOwner -> this
    is ContextWrapper -> baseContext.lifecycleOwner()
    else -> throw IllegalStateException("No lifecycle owner")
}
