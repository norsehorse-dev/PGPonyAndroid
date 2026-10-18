package com.pgpony.android.qr

import androidx.activity.ComponentActivity
import androidx.compose.material3.MaterialTheme
import android.content.res.Configuration
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.unit.dp
import androidx.compose.runtime.*
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.pgpony.android.R
import com.pgpony.android.ui.components.PublicKeyQrDisplay
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** UI tests exercise real asynchronous bitmap rendering, not camera throughput. */
@RunWith(AndroidJUnit4::class)
class QrPlaybackUiTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun sharedControlsKeepCompatibleDefaultAndAllowLargerModules() {
        val store = QrFrameStore.create("test".repeat(400))!!
        var selectedPolicy = QrEncodingPolicy.BASELINE
        compose.setContent {
            var policy by remember { mutableStateOf(selectedPolicy) }
            MaterialTheme {
                PublicKeyQrDisplay(store, policy, { policy = it; selectedPolicy = it })
            }
        }
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("public-key-qr-image").fetchSemanticsNodes().isNotEmpty()
        }
        assertEquals(QrEncodingPolicy.BASELINE, selectedPolicy)
        compose.onNodeWithText(compose.activity.getString(R.string.qr_density_roomy)).performClick()
        compose.runOnIdle { assertEquals(QrEncodingPolicy.ROBUST, selectedPolicy) }
        compose.onNodeWithText(compose.activity.getString(R.string.qr_density_normal)).performClick()
        compose.runOnIdle { assertEquals(QrEncodingPolicy.BASELINE, selectedPolicy) }
    }

    @Test fun enlargedViewPreservesPausedPartAndFingerprint() {
        val store = QrFrameStore.create("fixture".repeat(400))!!
        compose.setContent {
            MaterialTheme {
                PublicKeyQrDisplay(store, QrEncodingPolicy.BASELINE,
                    {}, fingerprint = "TEST FINGERPRINT")
            }
        }
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("public-key-qr-image").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithContentDescription(compose.activity.getString(R.string.qr_part_previous)).performClick()
        compose.onNodeWithText(compose.activity.getString(R.string.qr_enlarge)).performClick()
        compose.onNodeWithText("TEST FINGERPRINT").assertIsDisplayed()
        compose.waitUntil(10_000) {
            compose.onAllNodesWithText(compose.activity.getString(R.string.qr_part_of_format, store.frameCount, store.frameCount))
                .fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithContentDescription(compose.activity.getString(R.string.qr_autorotate_play_cd)).assertIsDisplayed()
        compose.onNodeWithText(compose.activity.getString(R.string.common_button_close)).performClick()
        compose.onNodeWithContentDescription(compose.activity.getString(R.string.qr_autorotate_play_cd)).assertIsDisplayed()
    }

    @Test fun wholeSymbolFitsAShortLandscapeWindow() {
        val store = QrFrameStore.create("fixture".repeat(400))!!
        compose.setContent {
            val shortWindow = Configuration(LocalConfiguration.current).apply {
                screenWidthDp = 900
                screenHeightDp = 400
                orientation = Configuration.ORIENTATION_LANDSCAPE
            }
            CompositionLocalProvider(LocalConfiguration provides shortWindow) {
                MaterialTheme {
                    PublicKeyQrDisplay(store, QrEncodingPolicy.BASELINE, {})
                }
            }
        }
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("public-key-qr-image").fetchSemanticsNodes().isNotEmpty()
        }
        val image = compose.onNodeWithTag("public-key-qr-image")
        val height = with(compose.density) { image.fetchSemanticsNode().boundsInRoot.height.toDp() }
        assertTrue("The complete symbol must fit the short viewport", height <= 220.dp)
        image.assertIsDisplayed()
    }

    @Test fun renderingFailureShowsActionableMessageInsteadOfAnEndlessSpinner() {
        compose.setContent {
            MaterialTheme {
                PublicKeyQrDisplay(null, QrEncodingPolicy.BASELINE,
                    {}, errorMessage = "Fixture export failed")
            }
        }
        compose.onNodeWithText("Fixture export failed").assertIsDisplayed()
    }
}
