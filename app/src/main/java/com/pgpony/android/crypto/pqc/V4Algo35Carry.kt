// V4Algo35Carry.kt
// PGPony Android, 4.6.0 (item 19): keep a v4 key's ML-KEM subkeys through an
// edit made with Bouncy Castle.
//
// A v4 key packet has no material-length field, so Bouncy Castle cannot parse
// a v4 algo-35 (ML-KEM-768 + X25519) subkey. It does not fail on one either:
// it loads the ring without it. Every key edit that went through a Bouncy
// Castle ring (add a subkey, add or revoke a User ID, change expiry, revoke or
// remove a subkey, change the passphrase, revoke the key) then stored that
// ring's encoding, and the ML-KEM subkey, secret and binding included, was
// gone. Adding a second ML-KEM subkey replaced the first the same way.
//
// [carry] puts them back: every v4 algo-35 subkey component (the key packet and
// the signatures that follow it) in the previously stored octets that the new
// octets do not already hold is added to the new octets, as a public or a
// secret packet to match them, ahead of any ML-KEM subkey the edit itself
// added so that the newest one stays last.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.CertificateBindings
import java.io.ByteArrayOutputStream

object V4Algo35Carry {

    private const val TAG_SECRET_KEY = 5
    private const val TAG_SECRET_SUBKEY = 7
    private const val TAG_PUBLIC_SUBKEY = 14
    private const val TAG_SIGNATURE = 2
    private const val TAG_TRUST = 12
    /** version(1) + ctime(4) + algo(1) + X25519(32) + ML-KEM-768(1184). */
    private const val V4_ALGO35_PUBLIC_LEN = 1 + 4 + 1 + 1216

    private class Component(val tag: Int, val body: ByteArray, val sigs: List<ByteArray>) {
        val publicBody: ByteArray get() = body.copyOfRange(0, V4_ALGO35_PUBLIC_LEN)
    }

    private fun isV4Algo35(tag: Int, body: ByteArray): Boolean =
        (tag == TAG_SECRET_SUBKEY || tag == TAG_PUBLIC_SUBKEY) &&
            body.size >= V4_ALGO35_PUBLIC_LEN &&
            (body[0].toInt() and 0xFF) == 4 && (body[5].toInt() and 0xFF) == 35

    private fun components(raw: ByteArray): List<Component> {
        val pkts = CertificateBindings.packets(raw)
        val out = ArrayList<Component>()
        var i = 0
        while (i < pkts.size) {
            val p = pkts[i]
            if (isV4Algo35(p.tag, p.body)) {
                val sigs = ArrayList<ByteArray>()
                var j = i + 1
                while (j < pkts.size && (pkts[j].tag == TAG_SIGNATURE || pkts[j].tag == TAG_TRUST)) {
                    if (pkts[j].tag == TAG_SIGNATURE) sigs.add(pkts[j].body)
                    j++
                }
                out.add(Component(p.tag, p.body, sigs))
                i = j
            } else i++
        }
        return out
    }

    /**
     * [newRaw] with every v4 algo-35 subkey of [oldRaw] it lacks added back.
     * [newRaw] unchanged when [oldRaw] is null or has none. [reprotect], when
     * given, rewrites a carried SECRET subkey body (a passphrase change).
     */
    fun carry(oldRaw: ByteArray?, newRaw: ByteArray, reprotect: ((ByteArray) -> ByteArray)? = null): ByteArray {
        if (oldRaw == null) return newRaw
        val old = components(oldRaw)
        if (old.isEmpty()) return newRaw
        val present = components(newRaw).map { it.publicBody }
        val missing = old.filter { c -> present.none { it.contentEquals(c.publicBody) } }
        if (missing.isEmpty()) return newRaw
        val newPkts = CertificateBindings.packets(newRaw)
        val newIsSecret = newPkts.firstOrNull()?.tag == TAG_SECRET_KEY
        // Carried subkeys go ahead of any algo-35 subkey the edit itself added,
        // so the newest one stays last (the one encryption picks).
        val firstNew = newPkts.indexOfFirst { isV4Algo35(it.tag, it.body) }
        val out = ByteArrayOutputStream()
        if (firstNew < 0) out.write(newRaw)
        else for (k in 0 until firstNew) out.write(CertificateBindings.frame(newPkts[k].tag, newPkts[k].body))
        for (c in missing) {
            val (tag, body) = when {
                !newIsSecret -> TAG_PUBLIC_SUBKEY to c.publicBody
                c.tag == TAG_SECRET_SUBKEY -> TAG_SECRET_SUBKEY to (reprotect?.invoke(c.body) ?: c.body)
                else -> TAG_PUBLIC_SUBKEY to c.publicBody
            }
            out.write(CertificateBindings.frame(tag, body))
            c.sigs.forEach { out.write(CertificateBindings.frame(TAG_SIGNATURE, it)) }
        }
        if (firstNew >= 0) for (k in firstNew until newPkts.size) {
            out.write(CertificateBindings.frame(newPkts[k].tag, newPkts[k].body))
        }
        return out.toByteArray()
    }

    /**
     * A v4 algo-35 secret subkey body re-protected from [oldPassphrase] to
     * [newPassphrase] (null or empty = unprotected), for [carry] during a
     * passphrase change. Throws when [oldPassphrase] does not unlock it.
     */
    fun reprotectBody(body: ByteArray, oldPassphrase: CharArray?, newPassphrase: CharArray?): ByteArray {
        val material = V4Algo35Protection.unlock(body, oldPassphrase)
            ?: return body // public-only: nothing to protect
        val pub = body.copyOfRange(0, V4_ALGO35_PUBLIC_LEN)
        val region = if (newPassphrase == null || newPassphrase.isEmpty()) {
            var sum = 0
            for (b in material) sum = (sum + (b.toInt() and 0xFF)) and 0xFFFF
            byteArrayOf(0) + material + byteArrayOf(((sum ushr 8) and 0xFF).toByte(), (sum and 0xFF).toByte())
        } else {
            V4Algo35Protection.protect(material, newPassphrase)
        }
        return pub + region
    }
}
