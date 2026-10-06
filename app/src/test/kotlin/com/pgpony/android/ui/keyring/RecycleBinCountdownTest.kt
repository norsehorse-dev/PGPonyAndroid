// RecycleBinCountdownTest.kt
// PGPony Android 4.6.4 (#58): days left on each key in Recently Deleted.

package com.pgpony.android.ui.keyring

import com.pgpony.android.data.repository.KeyRepository
import org.junit.Assert.assertEquals
import org.junit.Test

class RecycleBinCountdownTest {

    private val day = 24L * 60 * 60 * 1000
    private val hour = 60L * 60 * 1000
    private val deletedAt = 1_700_000_000_000L
    private val retention = KeyRepository.RECYCLE_BIN_RETENTION_DAYS

    @Test
    fun justDeleted_showsTheFullRetention() {
        assertEquals(retention, RecycleBinCountdown.daysLeft(deletedAt, deletedAt + 60_000))
    }

    @Test
    fun atDeletionInstant_showsTheFullRetention() {
        assertEquals(retention, RecycleBinCountdown.daysLeft(deletedAt, deletedAt))
    }

    @Test
    fun midway_roundsToTheNearestDay() {
        assertEquals(retention - 3, RecycleBinCountdown.daysLeft(deletedAt, deletedAt + 3 * day + 5 * hour))
        assertEquals(retention - 4, RecycleBinCountdown.daysLeft(deletedAt, deletedAt + 3 * day + 13 * hour))
    }

    @Test
    fun justOverOneDayLeft_isOne() {
        val now = deletedAt + KeyRepository.RECYCLE_BIN_RETENTION_MS - day - hour
        assertEquals(1, RecycleBinCountdown.daysLeft(deletedAt, now))
    }

    @Test
    fun lastDay_isZero() {
        val now = deletedAt + KeyRepository.RECYCLE_BIN_RETENTION_MS - 23 * hour
        assertEquals(0, RecycleBinCountdown.daysLeft(deletedAt, now))
    }

    @Test
    fun pastRetentionAwaitingPurge_isZero() {
        val now = deletedAt + KeyRepository.RECYCLE_BIN_RETENTION_MS + day
        assertEquals(0, RecycleBinCountdown.daysLeft(deletedAt, now))
    }
}
