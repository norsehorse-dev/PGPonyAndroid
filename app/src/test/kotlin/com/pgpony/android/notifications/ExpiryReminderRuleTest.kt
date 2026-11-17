// ExpiryReminderRuleTest.kt
// PGPony Android 4.8.1 (#125): a tester got "Your PGP key expires" for a
// contact's public key. Reminders are for the user's own keys only, and an
// alarm already set posts only while it still fits the key.

package com.pgpony.android.notifications

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.TrustLevel
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ExpiryReminderRuleTest {

    private val day = 24L * 60L * 60L * 1000L
    private val now = 1_800_000_000_000L

    private fun key(
        keyPair: Boolean = false,
        card: Boolean = false,
        revoked: Boolean = false,
        deletedAt: Long? = null,
        expiresAt: Long? = now + 30 * day
    ) = PGPKeyEntity(
        id = "id",
        fingerprint = "AAAAAAAAAAAAAAAAAAAAAAAA1111111111111111",
        userID = "K <k@example.org>",
        userName = "K",
        userEmail = "k@example.org",
        algorithm = KeyAlgorithm.ED25519_CV25519,
        isKeyPair = keyPair,
        isCardBacked = card,
        trustLevel = TrustLevel.UNKNOWN,
        createdAt = 0L,
        expiresAt = expiresAt,
        isDefault = false,
        isRevoked = revoked,
        deletedAt = deletedAt
    )

    @Test
    fun `a contact's public key gets no reminders`() {
        assertFalse(ExpiryReminderRule.remindsFor(key()))
        assertFalse(ExpiryReminderRule.stillDue(key(), 30, now))
    }

    @Test
    fun `own keys get reminders, on the phone or on a card`() {
        assertTrue(ExpiryReminderRule.remindsFor(key(keyPair = true)))
        assertTrue(ExpiryReminderRule.remindsFor(key(card = true)))
    }

    @Test
    fun `revoked, binned or never-expiring keys get none`() {
        assertFalse(ExpiryReminderRule.remindsFor(key(keyPair = true, revoked = true)))
        assertFalse(ExpiryReminderRule.remindsFor(key(keyPair = true, deletedAt = now)))
        assertFalse(ExpiryReminderRule.remindsFor(key(keyPair = true, expiresAt = null)))
    }

    @Test
    fun `an alarm posts while it fits the key's expiry`() {
        val k = key(keyPair = true, expiresAt = now + 30 * day)
        assertTrue(ExpiryReminderRule.stillDue(k, 30, now))
        assertTrue(ExpiryReminderRule.stillDue(k, 30, now + 3 * 60 * 60 * 1000L))
        // The day-of alarm fires at the expiry itself.
        assertTrue(ExpiryReminderRule.stillDue(k, 0, now + 30 * day))
    }

    @Test
    fun `an alarm for a key whose expiry moved, or that is gone, posts nothing`() {
        val extended = key(keyPair = true, expiresAt = now + 400 * day)
        assertFalse(ExpiryReminderRule.stillDue(extended, 30, now))
        assertFalse(ExpiryReminderRule.stillDue(null, 30, now))
    }
}
