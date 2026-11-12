// SubkeyPick.kt
// PGPony Android, 4.8.0 RC11 (#109): the rules behind the subkey picker that
// Add subkey (Key Details) and the composer (Generate Key) share. The RC10 and
// early RC11 builds listed every kind in one long menu, with the curve for
// ECDSA and ECDH set in a row of its own that renamed four entries under it.
// The picker asks three short questions instead: what the subkey is for, its
// type, and (when the type has more than one) its curve or size. Each answer
// starts on what fits the key: the first use the key does not have yet, the
// primary's own family, the primary's own curve or size.

package com.pgpony.android.ui.keyring

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.CompositeSuite

object SubkeyPick {

    /**
     * A subkey type, the same across uses so a pick survives a change of use:
     * Ed25519 signs and authenticates and X25519 encrypts (CURVE25519), ECDSA
     * signs and authenticates and ECDH encrypts on the same curve (EC), RSA does
     * all three, ML-DSA signs and ML-KEM encrypts (PQ).
     */
    enum class Kind { CURVE25519, EC, RSA, PQ }

    fun kindOf(choice: AddSubkeyChoice): Kind = when (choice) {
        is AddSubkeyChoice.Classical -> when {
            choice.type.curve != null -> Kind.EC
            choice.type.name.startsWith("RSA") -> Kind.RSA
            else -> Kind.CURVE25519
        }
        else -> Kind.PQ
    }

    /**
     * Every subkey [base] takes, on every curve: AddSubkeyChoice.optionsFor once
     * per curve, merged. Grouped by use, and within a use [primary]'s family first.
     */
    fun options(
        base: AddSubkeyChoice.Base,
        postQuantum: Boolean = true,
        primary: KeyAlgorithm? = null
    ): List<AddSubkeyChoice> = KeyAlgorithm.generatableEcdsa
        .flatMap { AddSubkeyChoice.optionsFor(base, it, postQuantum, primary) }
        .distinct()
        .sortedBy { AddSubkeyChoice.usageOf(it).ordinal }

    fun usages(options: List<AddSubkeyChoice>): List<AddSubkeyChoice.Usage> =
        AddSubkeyChoice.Usage.entries.filter { u -> options.any { AddSubkeyChoice.usageOf(it) == u } }

    fun kinds(options: List<AddSubkeyChoice>, usage: AddSubkeyChoice.Usage): List<Kind> =
        options.filter { AddSubkeyChoice.usageOf(it) == usage }.map { kindOf(it) }.distinct()

    /** The curves, sizes or levels of one type for one use, in list order. */
    fun variants(options: List<AddSubkeyChoice>, usage: AddSubkeyChoice.Usage, kind: Kind): List<AddSubkeyChoice> =
        options.filter { AddSubkeyChoice.usageOf(it) == usage && kindOf(it) == kind }

    /**
     * The use the picker starts on: the first one in [options] the key does not
     * [have] yet, encryption before authentication (a key that cannot be
     * encrypted to is the bigger gap), or the first use when it has them all.
     */
    fun startUsage(options: List<AddSubkeyChoice>, have: Set<AddSubkeyChoice.Usage>): AddSubkeyChoice.Usage? {
        val all = usages(options)
        return START_ORDER.firstOrNull { it in all && it !in have } ?: all.firstOrNull()
    }

    private val START_ORDER = listOf(AddSubkeyChoice.Usage.SIGN, AddSubkeyChoice.Usage.ENCRYPT, AddSubkeyChoice.Usage.AUTHENTICATE)

    /** The subkey the picker starts on. */
    fun start(
        options: List<AddSubkeyChoice>,
        have: Set<AddSubkeyChoice.Usage>,
        primary: KeyAlgorithm?
    ): AddSubkeyChoice? = startUsage(options, have)?.let { pick(options, it, null, null, primary) }

    /**
     * The subkey for [usage]: of [kind] when that use has it (its first type
     * otherwise), and among that type's variants the one like [like] (same curve,
     * same RSA size, same post-quantum level), else the one matching [primary],
     * else RSA 4096 or the first.
     */
    fun pick(
        options: List<AddSubkeyChoice>,
        usage: AddSubkeyChoice.Usage,
        kind: Kind?,
        like: AddSubkeyChoice?,
        primary: KeyAlgorithm?
    ): AddSubkeyChoice? {
        val kinds = kinds(options, usage)
        val k = kind?.takeIf { it in kinds } ?: kinds.firstOrNull() ?: return null
        val vs = variants(options, usage, k)
        like?.let { l -> vs.firstOrNull { sameVariant(it, l) }?.let { return it } }
        vs.firstOrNull { matchesPrimary(it, primary) }?.let { return it }
        return vs.firstOrNull { rsaBits(it) == 4096 } ?: vs.firstOrNull()
    }

    /** The subkey of the same type and variant for another use, for when the use changes. */
    fun withUsage(
        options: List<AddSubkeyChoice>,
        current: AddSubkeyChoice,
        usage: AddSubkeyChoice.Usage,
        primary: KeyAlgorithm?
    ): AddSubkeyChoice? = pick(options, usage, kindOf(current), current, primary)

    /** Another type for the same use, keeping the variant when it can. */
    fun withKind(
        options: List<AddSubkeyChoice>,
        current: AddSubkeyChoice,
        kind: Kind,
        primary: KeyAlgorithm?
    ): AddSubkeyChoice? = pick(options, AddSubkeyChoice.usageOf(current), kind, current, primary)

    private fun curveOf(c: AddSubkeyChoice): KeyAlgorithm? = (c as? AddSubkeyChoice.Classical)?.type?.curve

    fun rsaBits(c: AddSubkeyChoice): Int? = (c as? AddSubkeyChoice.Classical)?.type?.name?.let {
        when {
            it.startsWith("RSA_2048") -> 2048
            it.startsWith("RSA_4096") -> 4096
            else -> null
        }
    }

    /** 0 for ML-DSA-65 and ML-KEM-768, 1 for ML-DSA-87 and ML-KEM-1024. */
    fun pqLevel(c: AddSubkeyChoice): Int? = when (c) {
        is AddSubkeyChoice.PqSigning -> if (c.suite == CompositeSignSuite.MLDSA87_ED448) 1 else 0
        is AddSubkeyChoice.PqEncryption -> if (c.suite == CompositeSuite.IETF_1024) 1 else 0
        else -> null
    }

    private fun sameVariant(a: AddSubkeyChoice, b: AddSubkeyChoice): Boolean = when {
        curveOf(a) != null -> curveOf(a) == curveOf(b)
        rsaBits(a) != null -> rsaBits(a) == rsaBits(b)
        pqLevel(a) != null -> pqLevel(a) == pqLevel(b)
        else -> false
    }

    private fun matchesPrimary(c: AddSubkeyChoice, primary: KeyAlgorithm?): Boolean = when {
        primary == null -> false
        curveOf(c) != null -> curveOf(c) == primary
        rsaBits(c) != null -> (primary == KeyAlgorithm.RSA_2048 && rsaBits(c) == 2048) ||
            (primary == KeyAlgorithm.RSA_4096 && rsaBits(c) == 4096)
        else -> false
    }

    /**
     * The uses a key in Key Details already covers, for where the picker starts:
     * signing always (the primary signs, or a signing subkey was made with it),
     * plus every use in [usableSubkeyFlags], the key flags of its subkeys that
     * are usable now.
     */
    fun haveFrom(usableSubkeyFlags: List<Int>): Set<AddSubkeyChoice.Usage> {
        val have = mutableSetOf(AddSubkeyChoice.Usage.SIGN)
        usableSubkeyFlags.forEach { f ->
            if (f and 0x04 != 0) have += AddSubkeyChoice.Usage.ENCRYPT
            if (f and 0x08 != 0) have += AddSubkeyChoice.Usage.AUTHENTICATE
        }
        return have
    }
}
