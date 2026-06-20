// OnboardingScreen.kt
// PGPony Android
//
// First-run onboarding carousel. Shown on top of MainActivity's bottom-nav
// scaffold when SharedPreferences.onboarding_completed is false.
//
// Layout:
//   ┌───────────────────────────────┐
//   │                         Skip  │   ← top bar (hidden on last page)
//   ├───────────────────────────────┤
//   │         HorizontalPager       │   ← OnboardingPage swipeable
//   ├───────────────────────────────┤
//   │  ●○○○○         [Next/Done]   │   ← dot indicator + advance button
//   └───────────────────────────────┘
//
// Phase 3.1: Accepts a KeyringViewModel so slide 2 can offer inline key
// generation. When that succeeds, the pager auto-advances to slide 3.

package com.pgpony.android.ui.onboarding

import android.content.SharedPreferences
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.pgpony.android.R
import com.pgpony.android.ui.keyring.KeyringViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OnboardingScreen(
    prefs: SharedPreferences,
    keyringVm: KeyringViewModel,
    onComplete: () -> Unit
) {
    val slides = OnboardingSlides.all
    val pagerState = rememberPagerState(pageCount = { slides.size })
    val scope = rememberCoroutineScope()

    val isLastPage = pagerState.currentPage == slides.lastIndex

    fun advanceToNext() {
        if (pagerState.currentPage < slides.lastIndex) {
            scope.launch {
                pagerState.animateScrollToPage(pagerState.currentPage + 1)
            }
        }
    }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Column(modifier = Modifier.fillMaxSize()) {

            // ── Top bar: Skip button (hidden on last page) ──────────────
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp)
                    .statusBarsPadding(),
                horizontalArrangement = Arrangement.End
            ) {
                if (!isLastPage) {
                    TextButton(
                        onClick = { onComplete() }
                    ) {
                        Text(
                            stringResource(R.string.onboarding_screen_skip),
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                } else {
                    // Spacer to preserve layout height
                    Box(modifier = Modifier.height(48.dp))
                }
            }

            // ── Pager ──────────────────────────────────────────────────
            HorizontalPager(
                state = pagerState,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
            ) { pageIndex ->
                OnboardingPage(
                    slide = slides[pageIndex],
                    prefs = prefs,
                    keyringVm = keyringVm,
                    onAdvance = { advanceToNext() }
                )
            }

            // ── Bottom bar: dot indicator + Next/Done button ───────────
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 20.dp)
                    .navigationBarsPadding(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                // Page indicator dots
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    slides.forEachIndexed { index, _ ->
                        val isActive = pagerState.currentPage == index
                        Box(
                            modifier = Modifier
                                .size(if (isActive) 10.dp else 8.dp)
                                .clip(CircleShape)
                                .background(
                                    if (isActive) Color(0xFF8B5CF6)
                                    else MaterialTheme.colorScheme.onSurfaceVariant
                                        .copy(alpha = 0.3f)
                                )
                        )
                    }
                }

                // Advance button
                Button(
                    onClick = {
                        if (isLastPage) {
                            onComplete()
                        } else {
                            advanceToNext()
                        }
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF8B5CF6)
                    ),
                    modifier = Modifier.height(48.dp)
                ) {
                    Text(
                        if (isLastPage) stringResource(R.string.onboarding_screen_get_started) else stringResource(R.string.onboarding_screen_next),
                        style = MaterialTheme.typography.titleMedium
                    )
                }
            }
        }
    }
}
