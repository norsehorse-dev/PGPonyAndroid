# PGPony Android — QR Scanner Fix

## Symptom
Camera opens, viewfinder draws, scanner sees the QR but never fires the result callback. Holding the camera over a QR for 20 seconds produces nothing.

## Root cause
Two classic CameraX + ZXing failure modes both present in `decodeQR()`:

### 1. Row-stride padding
CameraX's `ImageProxy.planes[0].buffer` for YUV_420_888 may have `rowStride > width` — the sensor / codec inserts alignment padding bytes at the end of each Y-plane row. The pre-fix code did `buffer.get(bytes)` which reads the whole padded buffer, then handed it to `PlanarYUVLuminanceSource` as if it were a tight grid. ZXing treated the padding bytes as luminance, scrambling the QR finder pattern (the three corner squares). Decode silently returned `NotFoundException`.

### 2. Rotation
Camera sensors are landscape-mounted; phones are usually held portrait. The Y plane comes out 90° rotated from what the user sees in the preview overlay. ZXing's QR finder pattern detector isn't fully rotation-invariant even with `TRY_HARDER` enabled. A portrait-displayed QR (the typical case — another phone showing the code in portrait orientation) reaches the decoder sideways and isn't recognized.

## Fix
One file. Three things:

1. **Strip row-stride padding** by walking the plane row-by-row and copying only the first `width` bytes into a tight `width × height` luminance buffer.
2. **Rotate the luminance buffer** by `imageProxy.imageInfo.rotationDegrees` (set by CameraX based on sensor orientation vs target rotation) so the QR finder pattern lands upright.
3. **Fallback to unrotated** if the rotated decode misses — handles edge cases like a phone laid flat on a table or a QR displayed at 90° from the scanner's portrait orientation.

The old `decodeQR()` function (12 lines) splits into three helpers: `decodeQR` orchestrates, `rotateYPlane` does the rotation math, `decodeYPlane` wraps the ZXing call. File grows from 246 → 359 lines, all additive.

## Deploy

    cp -R ~/Downloads/PGPonyAndroid_QRScannerFix/. ~/Apps/PGPonyAndroid/
    cd ~/Apps/PGPonyAndroid
    ./gradlew installDebug
    adb shell am start -n com.pgpony.android/.MainActivity

## Test
1. Display a PGPony public-key QR on one phone (Exchange tab → tap your key → QR).
2. On the other phone, open the Exchange tab → tap Scan.
3. **Expect:** the QR is detected within 1-2 seconds. Haptic success buzz fires. The import flow opens.
4. Try at different orientations (landscape too) — both should work since the rotation fallback handles either case.

## What this changes vs current tree

Only `app/src/main/java/com/pgpony/android/ui/scanner/QRScannerScreen.kt`. No other files touched. No new dependencies.
