package com.pgpony.android.ui

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.unit.dp

// #45 (CertainBot): the Decrypt tab needs a SOLID open padlock. The icon
// library's Icons.Filled.LockOpen renders hollow — unlike Icons.Filled.Lock,
// which is solid — so Decrypt was the one tab whose selected icon did not fill.
//
// This is Material's own lock_open geometry (the same shape as the unselected
// Icons.Outlined.LockOpen), with just the interior-carve subpath removed so the
// body fills, and the keyhole kept as a hole via even-odd. Because it is the
// exact Material path, the body height, position, and shackle orientation match
// the unselected outline exactly — selecting only swaps outline for solid, the
// same as every other tab. The fill colour is a placeholder; NavigationBarItem
// tints the whole icon, so it picks up the selected colour like the built-ins.
val DecryptLockOpen: ImageVector by lazy {
    ImageVector.Builder(
        name = "DecryptLockOpen",
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f
    ).apply {
        addPath(
            pathData = PathParser().parsePathString(
                "M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6h1.9c0-1.71 1.39-3.1 3.1-3.1 " +
                    "1.71 0 3.1 1.39 3.1 3.1v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 " +
                    "0 2-.9 2-2V10c0-1.1-.9-2-2-2z " +
                    "M12 17c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"
            ).toNodes(),
            fill = SolidColor(Color.Black),
            pathFillType = PathFillType.EvenOdd
        )
    }.build()
}
