package com.pgpony.android.qr

/**
 * Playback state for one immutable QR sequence, confined to the UI thread.
 * Create a new controller when the sequence changes, even if its frame count is unchanged.
 * A tick only advances a visible, fully rendered frame; manual navigation pauses playback.
 */
class QrPlaybackController(val frameCount: Int) {
    init { require(frameCount > 0) }

    var index: Int = 0
        private set
    var playing: Boolean = true
        private set

    fun toggle() { playing = !playing }

    fun next() {
        playing = false
        index = (index + 1) % frameCount
    }

    fun previous() {
        playing = false
        index = (index + frameCount - 1) % frameCount
    }

    fun tick(foreground: Boolean, frameReady: Boolean) {
        if (playing && foreground && frameReady) index = (index + 1) % frameCount
    }
}
