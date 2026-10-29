package at.yawk.password.app

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import at.yawk.password.model.Passkey
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val dateFormat = DateTimeFormatter.ISO_LOCAL_DATE

/**
 * The account of a passkey, e.g. "alice@example.com", or the display name if the relying party gave no user name.
 */
fun passkeyAccount(passkey: Passkey): String =
    passkey.userName.ifEmpty { passkey.userDisplayName }.ifEmpty { "(no user name)" }

private fun createdText(passkey: Passkey): String =
    if (passkey.created <= 0) {
        ""
    } else {
        "created " + dateFormat.format(Instant.ofEpochMilli(passkey.created).atZone(ZoneId.systemDefault()))
    }

/**
 * Shown on the unlock screen while a passkey request waits for the database to be unlocked.
 */
@Composable
internal fun PasskeyRequestBanner(request: PasskeyRequest, viewModel: PasswordViewModel) {
    Row(
        Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.secondaryContainer).padding(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        val what = when (request) {
            is PasskeyRequest.Create -> "to create a passkey"
            is PasskeyRequest.Get -> "to sign in with a passkey"
        }
        Text(
            "${request.rpId} asks $what. Unlock the database to continue.",
            color = MaterialTheme.colorScheme.onSecondaryContainer,
            modifier = Modifier.weight(1f),
        )
        TextButton(onClick = { viewModel.answerPasskeyRequest(request, PasskeyAnswer.Dismiss) }) { Text("Refuse") }
    }
}

/**
 * Asks the user to answer a passkey request while the database is unlocked.
 */
@Composable
internal fun PasskeyRequestDialog(request: PasskeyRequest, state: UiState.Unlocked, viewModel: PasswordViewModel) {
    val dismiss = { viewModel.answerPasskeyRequest(request, PasskeyAnswer.Dismiss) }
    val approve = { passkey: Passkey? ->
        // the user is told below that this replaces the server copy
        if (state.fromLocalStorage) viewModel.confirmOfflineSave()
        viewModel.answerPasskeyRequest(request, PasskeyAnswer.Approve(passkey))
    }
    // like ConfirmDialog, the safe choice has the focus
    val cancelFocus = remember(request) { FocusRequester() }
    LaunchedEffect(request) { cancelFocus.requestFocus() }
    val cancelButton = @Composable {
        TextButton(onClick = dismiss, modifier = Modifier.focusRequester(cancelFocus)) { Text("Cancel") }
    }
    val offlineWarning = if (state.fromLocalStorage && !state.offlineSaveConfirmed) {
        "\n\nThe database was loaded from the local copy, not from the server. Saving replaces the server copy with " +
            "this version."
    } else {
        ""
    }
    when (request) {
        is PasskeyRequest.Create -> {
            val excluded = request.excluded(state.passkeys)
            if (excluded != null) {
                AlertDialog(
                    onDismissRequest = dismiss,
                    title = { Text("Passkey exists") },
                    text = { Text("The database already has a passkey for ${passkeyAccount(excluded)} at ${request.rpId}.") },
                    confirmButton = {
                        Button(onClick = dismiss, modifier = Modifier.focusRequester(cancelFocus)) { Text("OK") }
                    },
                )
            } else {
                val passkey = request.passkey
                val replaced = state.passkeys.firstOrNull {
                    it.rpId == passkey.rpId && it.userHandle == passkey.userHandle
                }
                val name = buildString {
                    append(passkeyAccount(passkey))
                    if (passkey.userDisplayName.isNotEmpty() && passkey.userDisplayName != passkey.userName) {
                        append(" (").append(passkey.userDisplayName).append(")")
                    }
                }
                AlertDialog(
                    onDismissRequest = dismiss,
                    title = { Text("Create passkey") },
                    text = {
                        Text(
                            "${request.rpId} asks to create a passkey for $name. It is saved in the password " +
                                "database." +
                                (if (replaced != null) " It replaces the passkey of this account created earlier." else "") +
                                offlineWarning,
                        )
                    },
                    confirmButton = { Button(onClick = { approve(null) }, enabled = !state.busy) { Text("Create") } },
                    dismissButton = cancelButton,
                )
            }
        }
        is PasskeyRequest.Get -> {
            val candidates = request.candidates(state.passkeys)
            if (candidates.isEmpty()) {
                AlertDialog(
                    onDismissRequest = dismiss,
                    title = { Text("No passkey") },
                    text = { Text("${request.rpId} asks to sign in with a passkey, but the database has none for it.") },
                    confirmButton = {
                        Button(onClick = dismiss, modifier = Modifier.focusRequester(cancelFocus)) { Text("OK") }
                    },
                )
            } else {
                AlertDialog(
                    onDismissRequest = dismiss,
                    title = { Text("Sign in with a passkey") },
                    text = {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("${request.rpId} asks to sign in. Choose the account:")
                            LazyColumn(Modifier.heightIn(max = 320.dp)) {
                                items(candidates) { passkey ->
                                    PasskeyRow(passkey, enabled = !state.busy, onClick = { approve(passkey) })
                                }
                            }
                        }
                    },
                    confirmButton = {},
                    dismissButton = cancelButton,
                )
            }
        }
    }
}

@Composable
private fun PasskeyRow(passkey: Passkey, enabled: Boolean, onClick: () -> Unit) {
    Column(
        Modifier.fillMaxWidth().clickable(enabled = enabled, onClick = onClick).padding(vertical = 8.dp),
    ) {
        Text(passkeyAccount(passkey), maxLines = 1, overflow = TextOverflow.Ellipsis)
        val details = listOf(passkey.userDisplayName.takeIf { it != passkey.userName }.orEmpty(), createdText(passkey))
            .filter { it.isNotEmpty() }.joinToString(" · ")
        if (details.isNotEmpty()) {
            Text(
                details,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/**
 * The passkeys of the database, by relying party, each with a delete button.
 */
@Composable
internal fun PasskeysDialog(passkeys: List<Passkey>, idle: Boolean, onDelete: (Passkey) -> Unit, onDismiss: () -> Unit) {
    val closeFocus = remember { FocusRequester() }
    LaunchedEffect(Unit) { closeFocus.requestFocus() }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Passkeys") },
        text = {
            if (passkeys.isEmpty()) {
                Text(
                    "The database has no passkeys yet. Websites and apps create them through Android's credential " +
                        "manager, or through the desktop app's security key.",
                )
            } else {
                LazyColumn(Modifier.heightIn(max = 400.dp)) {
                    val sorted = passkeys.sortedWith(compareBy({ it.rpId }, { passkeyAccount(it) }))
                    items(sorted) { passkey ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f).padding(vertical = 8.dp)) {
                                Text(passkey.rpId, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text(
                                    listOf(passkeyAccount(passkey), createdText(passkey))
                                        .filter { it.isNotEmpty() }.joinToString(" · "),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                            TextButton(onClick = { onDelete(passkey) }, enabled = idle) { Text("Delete") }
                        }
                        HorizontalDivider()
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = onDismiss, modifier = Modifier.focusRequester(closeFocus)) { Text("Close") }
        },
    )
}
