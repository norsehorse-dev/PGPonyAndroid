// PairCrypto.kt
// The key exchange and derivations of the pairing protocol (docs/PAIRING_PROTOCOL.md, sections
// 3 and 5). X25519 from Bouncy Castle's lightweight API and everything else from javax.crypto,
// which Android and the desktop JVM both provide.

package com.pgpony.android.pair

import org.bouncycastle.math.ec.rfc7748.X25519
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object PairCrypto {

    private val random = SecureRandom()

    private val LABEL_COMMIT = ascii("pgpony/pair/commit/v1")
    private val LABEL_TRANSCRIPT = ascii("pgpony/pair/transcript/v1")
    private val LABEL_KEY = ascii("pgpony/pair/key/v1")
    private val LABEL_HOST_TO_JOINER = ascii("pgpony/pair/host-to-joiner/v1")
    private val LABEL_JOINER_TO_HOST = ascii("pgpony/pair/joiner-to-host/v1")
    private val LABEL_CODE = ascii("pgpony/pair/code/v1")
    private val LABEL_MESSAGE = ascii("pgpony/pair/msg/v1")

    private fun ascii(s: String) = s.toByteArray(Charsets.US_ASCII)

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }

    /** An X25519 key pair: (secret, public). */
    class KeyPair(val secret: ByteArray, val public: ByteArray) {
        fun wipe() = secret.fill(0)
    }

    fun keyPair(secret: ByteArray = randomBytes(32)): KeyPair {
        val pub = ByteArray(32)
        X25519.scalarMultBase(secret, 0, pub, 0)
        return KeyPair(secret.copyOf(), pub)
    }

    /** X25519(secret, peer); null when the result is all zero (a low-order peer key). */
    fun agree(secret: ByteArray, peer: ByteArray): ByteArray? {
        val z = ByteArray(32)
        return if (X25519.calculateAgreement(secret, 0, peer, 0, z, 0)) z else null
    }

    fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        parts.forEach { mac.update(it) }
        return mac.doFinal()
    }

    fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        parts.forEach { md.update(it) }
        return md.digest()
    }

    fun commit(nonceHost: ByteArray, pkHost: ByteArray, pkJoiner: ByteArray): ByteArray =
        hmac(nonceHost, LABEL_COMMIT, pkHost, pkJoiner)

    fun transcript(pkJ: ByteArray, pkH: ByteArray, nJ: ByteArray, nH: ByteArray): ByteArray =
        sha256(LABEL_TRANSCRIPT, pkJ, pkH, nJ, nH)

    /** The three session keys (RFC 5869 HKDF-SHA256, one 32-byte block each). */
    class Keys(val pairKey: ByteArray, val hostToJoiner: ByteArray, val joinerToHost: ByteArray) {
        fun wipe() {
            pairKey.fill(0); hostToJoiner.fill(0); joinerToHost.fill(0)
        }
    }

    fun derive(z: ByteArray, transcript: ByteArray): Keys {
        val prk = hmac(transcript, z)
        fun expand(info: ByteArray) = hmac(prk, info, byteArrayOf(1))
        val keys = Keys(expand(LABEL_KEY), expand(LABEL_HOST_TO_JOINER), expand(LABEL_JOINER_TO_HOST))
        prk.fill(0)
        return keys
    }

    /** The six-digit comparison code, as shown: "042 917". */
    fun code(transcript: ByteArray): String {
        val h = sha256(LABEL_CODE, transcript)
        val v = ((h[0].toLong() and 0xFF) shl 24) or ((h[1].toLong() and 0xFF) shl 16) or
            ((h[2].toLong() and 0xFF) shl 8) or (h[3].toLong() and 0xFF)
        val digits = (v % 1_000_000).toString().padStart(6, '0')
        return digits.substring(0, 3) + " " + digits.substring(3)
    }

    fun seqBytes(seq: Long): ByteArray = ByteArray(8) { i -> (seq ushr (56 - 8 * i)).toByte() }

    /** `seq || AES-256-GCM(...)` (section 5). */
    fun seal(key: ByteArray, seq: Long, plaintext: ByteArray): ByteArray {
        val s = seqBytes(seq)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, ByteArray(4) + s))
        c.updateAAD(LABEL_MESSAGE)
        c.updateAAD(s)
        return s + c.doFinal(plaintext)
    }

    /** The plaintext of a sealed message whose sequence number must be [expectedSeq]. */
    fun open(key: ByteArray, expectedSeq: Long, sealed: ByteArray): ByteArray {
        if (sealed.size < 8 + 16) throw PairException(PairFailure.PROTOCOL, "short message")
        val s = sealed.copyOfRange(0, 8)
        if (!s.contentEquals(seqBytes(expectedSeq))) throw PairException(PairFailure.PROTOCOL, "message out of order")
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, ByteArray(4) + s))
        c.updateAAD(LABEL_MESSAGE)
        c.updateAAD(s)
        return try {
            c.doFinal(sealed, 8, sealed.size - 8)
        } catch (e: javax.crypto.AEADBadTagException) {
            throw PairException(PairFailure.PROTOCOL, "message failed authentication")
        }
    }
}
