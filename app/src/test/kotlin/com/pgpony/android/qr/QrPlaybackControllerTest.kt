package com.pgpony.android.qr
import org.junit.Assert.*
import org.junit.Test
class QrPlaybackControllerTest {
    @Test fun `manual stepping pauses and wraps`() {
        val player = QrPlaybackController(3)
        player.previous()
        assertEquals(2, player.index)
        assertFalse(player.playing)
        player.next()
        assertEquals(0, player.index)
    }
    @Test fun `automatic tick requires foreground ready frame and playback`() {
        val player = QrPlaybackController(3)
        player.tick(foreground = false, frameReady = true)
        player.tick(foreground = true, frameReady = false)
        assertEquals(0, player.index)
        player.tick(foreground = true, frameReady = true)
        assertEquals(1, player.index)
        player.toggle()
        player.tick(foreground = true, frameReady = true)
        assertEquals(1, player.index)
    }
    @Test fun `single frame never advances and empty is rejected`() {
        val player = QrPlaybackController(1)
        player.tick(true, true)
        assertEquals(0, player.index)
        assertThrows(IllegalArgumentException::class.java) { QrPlaybackController(0) }
    }
}
