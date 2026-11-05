package dev.ghostlypi.netdrop

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable

/**
 * Placeholder. Phase 4 replaces this with the peer list; Phase 5 adds the share-sheet
 * send flow (ACTION_SEND / ACTION_SEND_MULTIPLE, already declared in the manifest).
 *
 * Nothing here talks to Rust yet — `android/rust` is excluded from the cargo workspace
 * and every FFI method returns NotImplemented until netdrop-core exists. See
 * ../../../../../../README.md for the phase gate.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { Surface { Placeholder() } } }
    }
}

@Composable
private fun Placeholder() {
    Text("netdrop — scaffolding. See android/README.md.")
}
