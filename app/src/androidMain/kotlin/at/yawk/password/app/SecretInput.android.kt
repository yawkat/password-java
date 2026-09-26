package at.yawk.password.app

import android.text.InputType
import android.view.inputmethod.EditorInfo
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.InterceptPlatformTextInput
import androidx.compose.ui.platform.PlatformTextInputInterceptor
import androidx.compose.ui.platform.PlatformTextInputMethodRequest

/**
 * Compose has no keyboard option for these flags, so they are added to the [EditorInfo] that the text field passes to
 * the keyboard.
 */
private val secretInputInterceptor = PlatformTextInputInterceptor { request, nextHandler ->
    nextHandler.startInputMethod(
        PlatformTextInputMethodRequest { outAttributes ->
            val connection = request.createInputConnection(outAttributes)
            addSecretFlags(outAttributes)
            connection
        },
    )
}

/**
 * Don't learn from the input (IME_FLAG_NO_PERSONALIZED_LEARNING) and, for text, don't suggest anything
 * (TYPE_TEXT_FLAG_NO_SUGGESTIONS). Password fields have no suggestions anyway, but still need the first flag.
 */
internal fun addSecretFlags(editorInfo: EditorInfo) {
    editorInfo.imeOptions = editorInfo.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
    if (editorInfo.inputType and InputType.TYPE_MASK_CLASS == InputType.TYPE_CLASS_TEXT) {
        editorInfo.inputType = editorInfo.inputType or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
    }
}

@Composable
actual fun SecretInput(content: @Composable () -> Unit) =
    InterceptPlatformTextInput(secretInputInterceptor, content)
