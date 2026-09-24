// ApiClientAuthorizer.kt
// PGPony Android — 4.0.0 Succession Phase 1 (OpenPGP API provider)
//
// Decides whether a bound OpenPGP API client may talk to the provider
// service. The decision inputs are deliberately narrow so the class is
// unit-testable without Android: a DAO (allow-list rows) and a
// signature provider function (package name → lowercase hex SHA-256 of
// the signing cert, or null if unresolvable). The Android-specific
// signature lookup lives in the companion and is injected by the
// service; tests inject a fake.
//
// Decision table (no default-allow, ever):
//   • no row for the package            → UNKNOWN   (consent flow)
//   • row exists, signature matches     → AUTHORIZED
//   • row exists, signature differs     → SIGNATURE_MISMATCH (hard error;
//     the user must revoke the stale row in Settings → Connected apps
//     and re-consent — deliberate friction, this is the impostor case)
//   • signature unresolvable            → UNRESOLVABLE (hard error)
//
// 4.6.0: a grant is per scope (ApiClientEntity.SCOPE_OPENPGP, SCOPE_SSH). A
// row whose signature matches but lacks the requested scope is UNKNOWN for
// that scope, so the app gets that scope's own consent screen. Granting adds
// the bit; revoking a scope clears it (the SSH scope takes its key binding
// with it), and a row with no scopes left is deleted.

package com.pgpony.android.provider

import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.os.Build
import com.pgpony.android.data.ApiClientDao
import com.pgpony.android.data.ApiClientEntity
import java.security.MessageDigest

class ApiClientAuthorizer(
    private val dao: ApiClientDao,
    private val signatureSha256Of: (packageName: String) -> String?
) {

    enum class Decision {
        AUTHORIZED,
        UNKNOWN,
        SIGNATURE_MISMATCH,
        UNRESOLVABLE
    }

    suspend fun authorize(packageName: String, scope: Int): Decision {
        val currentSig = signatureSha256Of(packageName)
            ?: return Decision.UNRESOLVABLE
        val row = dao.getByPackage(packageName)
            ?: return Decision.UNKNOWN
        if (!row.signatureSha256.equals(currentSig, ignoreCase = true)) return Decision.SIGNATURE_MISMATCH
        return if (row.has(scope)) Decision.AUTHORIZED else Decision.UNKNOWN
    }

    /**
     * Record user consent for [scope], pinning the package's CURRENT signing
     * certificate. Adds [scope] to a row that already pins this certificate;
     * otherwise (no row, or a re-consent after the signing key changed) the
     * row is replaced and holds [scope] alone. Returns false when the
     * signature can't be resolved (app uninstalled between consent tap and
     * grant: don't store an unpinned row).
     */
    suspend fun grant(packageName: String, scope: Int, grantedAt: Long = System.currentTimeMillis()): Boolean {
        val sig = signatureSha256Of(packageName)?.lowercase() ?: return false
        val row = dao.getByPackage(packageName)
        if (row != null && row.signatureSha256.equals(sig, ignoreCase = true)) {
            dao.updateAccess(packageName, row.scopes or scope, row.sshKeyFingerprint)
        } else {
            dao.insert(ApiClientEntity(packageName, sig, grantedAt, scopes = scope))
        }
        return true
    }

    /** Remove the app entirely: every scope and the SSH key binding. */
    suspend fun revoke(packageName: String) {
        dao.deleteByPackage(packageName)
    }

    /**
     * Remove one [scope]. Removing SSH clears the SSH key binding; a row left
     * with no scope is deleted.
     */
    suspend fun revokeScope(packageName: String, scope: Int) {
        val row = dao.getByPackage(packageName) ?: return
        val left = row.scopes and scope.inv()
        if (left == 0) {
            dao.deleteByPackage(packageName)
        } else {
            val binding = if (left and ApiClientEntity.SCOPE_SSH != 0) row.sshKeyFingerprint else null
            dao.updateAccess(packageName, left, binding)
        }
    }

    /** The primary fingerprint the user picked for this app's SSH logins. */
    suspend fun sshKey(packageName: String): String? =
        dao.getByPackage(packageName)?.takeIf { it.has(ApiClientEntity.SCOPE_SSH) }?.sshKeyFingerprint

    /**
     * True only when [fingerprint] is the key bound to [packageName] for SSH.
     * An app with no binding yet, or asking for a different key, gets false,
     * and the SSH service shows the picker for the user to approve that key.
     */
    suspend fun sshKeyAllowed(packageName: String, fingerprint: String): Boolean =
        sshKey(packageName)?.equals(fingerprint, ignoreCase = true) == true

    /**
     * Bind this app's SSH logins to [fingerprint] (the key the user picked).
     * Only an app holding the SSH scope can be bound. Returns false otherwise.
     */
    suspend fun bindSshKey(packageName: String, fingerprint: String): Boolean {
        val row = dao.getByPackage(packageName) ?: return false
        if (!row.has(ApiClientEntity.SCOPE_SSH)) return false
        dao.updateAccess(packageName, row.scopes, fingerprint.uppercase())
        return true
    }

    companion object {
        /**
         * Android-side signature lookup: lowercase hex SHA-256 of the
         * package's first signing certificate. API 28+ uses the modern
         * signing-info API; 26–27 falls back to the deprecated
         * GET_SIGNATURES (safe here — we only READ the cert to hash it,
         * and the known fake-ID vulnerabilities concern chain VALIDATION,
         * which we don't do).
         *
         * Rotated keys: we hash the CURRENT cert (last in the rotation
         * history). A client that rotates its signing key will show as
         * SIGNATURE_MISMATCH and needs one re-consent — same behavior
         * OpenKeychain exhibits, and the safe default.
         */
        @SuppressLint("PackageManagerGetSignatures")
        @Suppress("DEPRECATION")
        fun platformSignatureLookup(pm: PackageManager): (String) -> String? = lookup@{ packageName ->
            try {
                val certBytes: ByteArray = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    val info = pm.getPackageInfo(
                        packageName, PackageManager.GET_SIGNING_CERTIFICATES
                    )
                    val signingInfo = info.signingInfo ?: return@lookup null
                    val signers = if (signingInfo.hasMultipleSigners()) {
                        signingInfo.apkContentsSigners
                    } else {
                        signingInfo.signingCertificateHistory
                    }
                    // signingCertificateHistory is ordered oldest → newest;
                    // pin the newest (current) certificate.
                    signers?.lastOrNull()?.toByteArray() ?: return@lookup null
                } else {
                    val info = pm.getPackageInfo(
                        packageName, PackageManager.GET_SIGNATURES
                    )
                    info.signatures?.firstOrNull()?.toByteArray() ?: return@lookup null
                }
                MessageDigest.getInstance("SHA-256")
                    .digest(certBytes)
                    .joinToString("") { "%02x".format(it) }
            } catch (e: PackageManager.NameNotFoundException) {
                null
            }
        }
    }
}
