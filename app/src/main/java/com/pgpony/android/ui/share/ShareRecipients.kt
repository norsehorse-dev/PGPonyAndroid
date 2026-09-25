// ShareRecipients.kt
// PGPony Android, 4.6.1 (#67): the share Quick Action's recipients, loaded the
// way the Encrypt screen loads them.
//
// The Quick Action used the plain BouncyCastle loader, which cannot read a
// composite ML-DSA key or a v4 key with an algo-35 (ML-KEM) subkey. Such a
// recipient came back as nothing: alone it failed with "no recipient keys",
// and next to other recipients it was silently left out, so the file was
// encrypted without it. Now each recipient goes through the same loaders as
// the Encrypt screen (the composite key's ML-KEM subkey, or the v4 algo-35
// channel), and any selected recipient that still cannot be loaded is
// reported, so the caller refuses to encrypt instead of dropping it.

package com.pgpony.android.ui.share

object ShareRecipients {

    class Loaded<R, V>(
        /** BouncyCastle rings to encrypt to. */
        val rings: List<R>,
        /** v4 Ed25519 + algo-35 recipients, carried on their own channel. */
        val v4Algo35: List<V>,
        /** Selected fingerprints that gave no encryption key at all. */
        val unusable: List<String>
    ) {
        val isComplete: Boolean get() = unusable.isEmpty()
        val isEmpty: Boolean get() = rings.isEmpty() && v4Algo35.isEmpty()
    }

    fun <R, V> load(
        fingerprints: Collection<String>,
        isV4Algo35: (String) -> Boolean,
        ring: (String) -> R?,
        v4Algo35: (String) -> V?
    ): Loaded<R, V> {
        val rings = mutableListOf<R>()
        val v4 = mutableListOf<V>()
        val unusable = mutableListOf<String>()
        for (fp in fingerprints) {
            if (isV4Algo35(fp)) {
                val r = v4Algo35(fp)
                if (r != null) { v4.add(r); continue }
            }
            val r = ring(fp)
            if (r != null) rings.add(r) else unusable.add(fp)
        }
        return Loaded(rings, v4, unusable)
    }
}
