// AppLockCore.kt
// PGPony Android 4.7.0 (item 32): the PGPony PIN app lock and its duress PIN.
//
// Plain Kotlin with no Android in it, so the hashing, the duress check, the
// attempt counter, the wipe threshold and the delay are unit tested on the
// JVM. AppLock (Android) wraps this with the file in filesDir, the lock screen
// and the wipe.
//
// What is stored is never a PIN. Each PIN is an Argon2id hash with its own
// random salt, tagged with a parameter version so the cost can change later
// without breaking a PIN set today. When no duress PIN is set, a random decoy
// salt sits in its place, so every attempt runs two hashes either way and
// compares both in constant time: the time an attempt takes tells neither the
// real PIN from the duress PIN nor whether a duress PIN exists.
//
// Both hashes in one config always share one version. A future version applies
// to the next PIN set up (a duress PIN cannot be re-hashed without knowing it).

package com.pgpony.android.lock

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.SecureRandom
import java.util.Base64

/** Argon2id cost for one PIN hash, by version. */
data class PinHashParams(
    val version: Int,
    val memoryKiB: Int,
    val iterations: Int,
    val parallelism: Int,
    val outputLength: Int
) {
    companion object {
        /**
         * Version 1: the cost the app already uses for Argon2id elsewhere, RFC 9580's
         * memory-constrained choice (S2K.Argon2Params.memoryConstrainedParameters:
         * 64 MiB, 3 passes, 4 lanes), with a 32-byte output.
         */
        val V1 = PinHashParams(version = 1, memoryKiB = 64 * 1024, iterations = 3, parallelism = 4, outputLength = 32)

        /**
         * Version 2 (Oct 13 on device): 32 MiB, 2 passes. Version 1 took 5 to 6
         * seconds per unlock on a mid-range phone, since every attempt runs two
         * hashes and Bouncy Castle's Argon2 uses one thread whatever the lane
         * count. The PIN hash is in app-private storage, so its cost is a speed
         * bump for an offline guesser who already has that file, not the main
         * defence; the wrong-PIN delay and wipe are. A PIN set under version 1
         * keeps it until the PIN is set again.
         */
        val V2 = PinHashParams(version = 2, memoryKiB = 32 * 1024, iterations = 2, parallelism = 4, outputLength = 32)

        val CURRENT: PinHashParams = V2

        /** The parameters for a stored version tag, or null for one this build does not know. */
        fun forVersion(version: Int): PinHashParams? = when (version) {
            1 -> V1
            2 -> V2
            else -> null
        }
    }
}

/** Hashes a PIN. Argon2PinHasher in the app; tests inject a fast, counting one. */
fun interface PinHasher {
    fun hash(pin: ByteArray, salt: ByteArray, params: PinHashParams): ByteArray
}

enum class PinFormat { OK, TOO_SHORT, TOO_LONG, NOT_DIGITS }

object PinRules {
    const val MIN_LENGTH = 6
    const val MAX_LENGTH = 16
    const val SALT_LENGTH = 16

    /** Wrong-PIN wipe choices offered in Settings; 0 is off (the default). */
    val WIPE_AFTER_CHOICES: List<Int> = listOf(0, 5, 10, 20)

    /** 6 to 16 ASCII digits. */
    fun check(pin: String): PinFormat = when {
        pin.any { it !in '0'..'9' } -> PinFormat.NOT_DIGITS
        pin.length < MIN_LENGTH -> PinFormat.TOO_SHORT
        pin.length > MAX_LENGTH -> PinFormat.TOO_LONG
        else -> PinFormat.OK
    }
}

/**
 * The delay after repeated wrong PINs, used when the wrong-PIN wipe is off.
 * Four free tries, then 30 seconds, 1, 2 and at most 5 minutes.
 */
object PinBackoff {
    const val FREE_ATTEMPTS = 4

    fun delayMs(failedAttempts: Int): Long = when {
        failedAttempts <= FREE_ATTEMPTS -> 0L
        failedAttempts == 5 -> 30_000L
        failedAttempts == 6 -> 60_000L
        failedAttempts == 7 -> 120_000L
        else -> 300_000L
    }
}

/**
 * A reading of the clock the delay is measured on: time since boot, which the
 * wall clock setting cannot move, and an identifier of that boot (Android's
 * Settings.Global.BOOT_COUNT), or null where the device does not have one.
 * Injected so tests drive it.
 */
data class LockClock(val elapsedMs: Long, val bootId: String?)

/** The stored app lock. Hashes and salts only; see the file header. */
data class AppLockConfig(
    val version: Int,
    val salt: ByteArray,
    val hash: ByteArray,
    /** The duress PIN's salt, or a decoy salt when no duress PIN is set. */
    val duressSalt: ByteArray,
    val duressHash: ByteArray?,
    val fingerprintAllowed: Boolean,
    /** Wipe after this many wrong PINs in a row; 0 is off. */
    val wipeAfter: Int,
    val failedAttempts: Int,
    /** [LockClock.elapsedMs] at the last wrong PIN, or -1 when there is none. */
    val lastFailureElapsedMs: Long,
    /** [LockClock.bootId] at the last wrong PIN. */
    val lastFailureBootId: String?
) {
    val hasDuress: Boolean get() = duressHash != null
}

/** The on-disk text form: one key=value per line, bytes in Base64. */
object AppLockCodec {
    const val FORMAT = "pgpony-app-lock"

    fun encode(c: AppLockConfig): String {
        val b64 = Base64.getEncoder()
        val sb = StringBuilder()
        sb.append("format=").append(FORMAT).append('\n')
        sb.append("v=").append(c.version).append('\n')
        sb.append("salt=").append(b64.encodeToString(c.salt)).append('\n')
        sb.append("hash=").append(b64.encodeToString(c.hash)).append('\n')
        sb.append("dsalt=").append(b64.encodeToString(c.duressSalt)).append('\n')
        c.duressHash?.let { sb.append("dhash=").append(b64.encodeToString(it)).append('\n') }
        sb.append("fp=").append(if (c.fingerprintAllowed) 1 else 0).append('\n')
        sb.append("wipe=").append(c.wipeAfter).append('\n')
        sb.append("fails=").append(c.failedAttempts).append('\n')
        sb.append("failrt=").append(c.lastFailureElapsedMs).append('\n')
        c.lastFailureBootId?.let { sb.append("failboot=").append(it).append('\n') }
        return sb.toString()
    }

    /** Null for text that is not a complete config. */
    fun decode(text: String): AppLockConfig? = try {
        val map = HashMap<String, String>()
        for (raw in text.lines()) {
            val line = raw.trim()
            val eq = line.indexOf('=')
            if (eq > 0) map[line.substring(0, eq)] = line.substring(eq + 1)
        }
        val b64 = Base64.getDecoder()
        if (map["format"] != FORMAT) {
            null
        } else {
            val salt = b64.decode(map.getValue("salt"))
            val hash = b64.decode(map.getValue("hash"))
            val duressSalt = b64.decode(map.getValue("dsalt"))
            val duressHash: ByteArray? = map["dhash"]?.let { b64.decode(it) }
            if (salt.isEmpty() || hash.isEmpty() || duressSalt.isEmpty()) {
                null
            } else {
                AppLockConfig(
                    version = map.getValue("v").toInt(),
                    salt = salt,
                    hash = hash,
                    duressSalt = duressSalt,
                    duressHash = duressHash,
                    fingerprintAllowed = map["fp"] == "1",
                    wipeAfter = map["wipe"]?.toIntOrNull()?.coerceAtLeast(0) ?: 0,
                    failedAttempts = map["fails"]?.toIntOrNull()?.coerceAtLeast(0) ?: 0,
                    lastFailureElapsedMs = map["failrt"]?.toLongOrNull() ?: -1L,
                    lastFailureBootId = map["failboot"]?.takeIf { it.isNotEmpty() }
                )
            }
        }
    } catch (_: Exception) {
        null
    }
}

/** The outcome of one PIN attempt. */
sealed class PinCheck {
    data object Unlocked : PinCheck()
    /** The duress PIN: the caller wipes, silently. */
    data object Duress : PinCheck()
    data class Wrong(val failedAttempts: Int, val delayMs: Long) : PinCheck()
    /** A wrong PIN that reached the wrong-PIN wipe threshold: the caller wipes. */
    data class WipeLimit(val failedAttempts: Int) : PinCheck()
    /** Still inside the delay: nothing was hashed and nothing counted. */
    data class Throttled(val remainingMs: Long) : PinCheck()
    /** No usable config (missing, unreadable, or a version this build does not know). */
    data object Unsupported : PinCheck()
}

/** [updated] is what to persist after the attempt, or null when nothing changed. */
class PinCheckResult(val outcome: PinCheck, val updated: AppLockConfig?)

/** The outcome of setting or changing a PIN. */
sealed class PinSetup {
    data class Done(val config: AppLockConfig) : PinSetup()
    data class Invalid(val format: PinFormat) : PinSetup()
    /** The new PIN equals the other one (duress equal to the PIN, or the reverse). */
    data object SameAsOther : PinSetup()
    data object Unsupported : PinSetup()
}

/** Equal length and bytes, without an early exit on the first difference. */
fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
    var diff = a.size xor b.size
    val n = minOf(a.size, b.size)
    for (i in 0 until n) diff = diff or (a[i].toInt() xor b[i].toInt())
    return diff == 0
}

private val secureRandom = SecureRandom()

fun secureRandomBytes(n: Int): ByteArray = ByteArray(n).also { secureRandom.nextBytes(it) }

class AppLockCore(
    private val hasher: PinHasher,
    private val randomBytes: (Int) -> ByteArray = ::secureRandomBytes,
    private val params: PinHashParams = PinHashParams.CURRENT,
    /** Version tag to parameters; tests map a cheap cost onto version 1. */
    private val paramsFor: (Int) -> PinHashParams? = { v -> PinHashParams.forVersion(v) }
) {

    private fun hashOf(pin: String, salt: ByteArray, p: PinHashParams): ByteArray {
        val bytes = pin.toByteArray(Charsets.US_ASCII)
        return try {
            hasher.hash(bytes, salt, p)
        } finally {
            bytes.fill(0)
        }
    }

    /** A new PGPony PIN, with a decoy duress salt and no duress PIN. */
    fun create(pin: String, fingerprintAllowed: Boolean): PinSetup {
        val format = PinRules.check(pin)
        if (format != PinFormat.OK) return PinSetup.Invalid(format)
        val salt = randomBytes(PinRules.SALT_LENGTH)
        return PinSetup.Done(
            AppLockConfig(
                version = params.version,
                salt = salt,
                hash = hashOf(pin, salt, params),
                duressSalt = randomBytes(PinRules.SALT_LENGTH),
                duressHash = null,
                fingerprintAllowed = fingerprintAllowed,
                wipeAfter = 0,
                failedAttempts = 0,
                lastFailureElapsedMs = -1L,
                lastFailureBootId = null
            )
        )
    }

    /** Replace the PIN; refused when it equals the duress PIN. Keeps the duress PIN. */
    fun changePin(config: AppLockConfig, newPin: String): PinSetup {
        val format = PinRules.check(newPin)
        if (format != PinFormat.OK) return PinSetup.Invalid(format)
        val p = paramsFor(config.version) ?: return PinSetup.Unsupported
        val duressHash = config.duressHash
        if (duressHash != null && constantTimeEquals(hashOf(newPin, config.duressSalt, p), duressHash)) {
            return PinSetup.SameAsOther
        }
        val salt = randomBytes(PinRules.SALT_LENGTH)
        return PinSetup.Done(
            config.copy(salt = salt, hash = hashOf(newPin, salt, p), failedAttempts = 0, lastFailureElapsedMs = -1L, lastFailureBootId = null)
        )
    }

    /** Set (or replace) the duress PIN; refused when it equals the PIN. */
    fun setDuress(config: AppLockConfig, duressPin: String): PinSetup {
        val format = PinRules.check(duressPin)
        if (format != PinFormat.OK) return PinSetup.Invalid(format)
        val p = paramsFor(config.version) ?: return PinSetup.Unsupported
        if (constantTimeEquals(hashOf(duressPin, config.salt, p), config.hash)) return PinSetup.SameAsOther
        val salt = randomBytes(PinRules.SALT_LENGTH)
        return PinSetup.Done(config.copy(duressSalt = salt, duressHash = hashOf(duressPin, salt, p)))
    }

    /** Drop the duress PIN; a fresh decoy salt keeps attempts at two hashes. */
    fun removeDuress(config: AppLockConfig): AppLockConfig =
        config.copy(duressSalt = randomBytes(PinRules.SALT_LENGTH), duressHash = null)

    /** A changed wipe threshold starts a fresh count. */
    fun withWipeAfter(config: AppLockConfig, wipeAfter: Int): AppLockConfig =
        config.copy(wipeAfter = wipeAfter.coerceAtLeast(0), failedAttempts = 0, lastFailureElapsedMs = -1L, lastFailureBootId = null)

    /** After an unlock by fingerprint: the owner is back, so the count starts over. */
    fun resetAttempts(config: AppLockConfig): AppLockConfig? =
        if (config.failedAttempts == 0 && config.lastFailureElapsedMs < 0L && config.lastFailureBootId == null) null
        else config.copy(failedAttempts = 0, lastFailureElapsedMs = -1L, lastFailureBootId = null)

    /**
     * True when [now] is on the boot the last wrong PIN was counted on, so the
     * time since then can be measured. A different boot, a clock reading
     * earlier than the stored one, or no stored reading all say no.
     */
    private fun sameBoot(config: AppLockConfig, now: LockClock): Boolean =
        config.lastFailureElapsedMs >= 0L &&
            config.lastFailureBootId == now.bootId &&
            now.elapsedMs >= config.lastFailureElapsedMs

    /**
     * Milliseconds left of the delay. None while the wrong-PIN wipe is on (the
     * threshold is the limit then). Measured on time since boot, so setting the
     * wall clock forward skips nothing; after a restart (another boot, or no
     * reading) the whole delay counts again from now, see [clockAdjusted].
     */
    fun throttleRemainingMs(config: AppLockConfig, now: LockClock): Long {
        if (config.wipeAfter > 0) return 0L
        val delay = PinBackoff.delayMs(config.failedAttempts)
        if (delay == 0L) return 0L
        if (!sameBoot(config, now)) return delay
        return (delay - (now.elapsedMs - config.lastFailureElapsedMs)).coerceAtLeast(0L)
    }

    /**
     * The config to persist when a delay is due but cannot be measured from the
     * stored reading: the delay restarts from [now]. Null otherwise.
     */
    fun clockAdjusted(config: AppLockConfig, now: LockClock): AppLockConfig? {
        if (config.wipeAfter > 0 || PinBackoff.delayMs(config.failedAttempts) == 0L) return null
        if (sameBoot(config, now)) return null
        return config.copy(lastFailureElapsedMs = now.elapsedMs, lastFailureBootId = now.bootId)
    }

    /**
     * One attempt. Outside the delay, always computes both hashes (the real
     * PIN's and the duress or decoy one) and compares both in constant time,
     * whatever was typed.
     */
    fun check(config: AppLockConfig, pin: String, now: LockClock): PinCheckResult {
        val remaining = throttleRemainingMs(config, now)
        if (remaining > 0L) return PinCheckResult(PinCheck.Throttled(remaining), clockAdjusted(config, now))
        val p = paramsFor(config.version) ?: return PinCheckResult(PinCheck.Unsupported, null)

        val bytes = pin.toByteArray(Charsets.US_ASCII)
        // 4.7.0 (item 32): the two hashes run side by side, the duress or decoy
        // one on a second thread, so an attempt takes the time of one hash.
        // Both are always computed and both finish before either is compared.
        val hashes: Pair<ByteArray, ByteArray> = try {
            var second: ByteArray? = null
            var secondError: Throwable? = null
            val worker = Thread {
                try {
                    second = hasher.hash(bytes, config.duressSalt, p)
                } catch (t: Throwable) {
                    secondError = t
                }
            }
            worker.start()
            val first = try {
                hasher.hash(bytes, config.salt, p)
            } finally {
                worker.join()
            }
            secondError?.let { throw it }
            Pair(first, second ?: throw IllegalStateException("duress hash missing"))
        } finally {
            bytes.fill(0)
        }
        val realCandidate = hashes.first
        val duressCandidate = hashes.second
        val realMatch = constantTimeEquals(realCandidate, config.hash)
        // With no duress PIN the decoy hash is still compared, against zeros of
        // the same length, so both cases do the same work.
        val duressTarget: ByteArray = config.duressHash ?: ByteArray(duressCandidate.size)
        val duressMatch = constantTimeEquals(duressCandidate, duressTarget) and config.hasDuress
        realCandidate.fill(0)
        duressCandidate.fill(0)

        return when {
            realMatch -> PinCheckResult(PinCheck.Unlocked, resetAttempts(config))
            duressMatch -> PinCheckResult(PinCheck.Duress, null)
            else -> {
                val fails = config.failedAttempts + 1
                val updated = config.copy(
                    failedAttempts = fails,
                    lastFailureElapsedMs = now.elapsedMs,
                    lastFailureBootId = now.bootId
                )
                if (config.wipeAfter > 0 && fails >= config.wipeAfter) {
                    PinCheckResult(PinCheck.WipeLimit(fails), updated)
                } else {
                    val delay = if (config.wipeAfter > 0) 0L else PinBackoff.delayMs(fails)
                    PinCheckResult(PinCheck.Wrong(fails, delay), updated)
                }
            }
        }
    }
}

/**
 * Atomic text write: a temp file, synced, renamed over the target, then the
 * directory synced. There is no non-atomic fallback: a failed rename throws
 * and leaves the old file as it was.
 *
 * 4.8.0 (desktop 3.1.0): the rename is Files.move with ATOMIC_MOVE, not
 * File.renameTo. renameTo replaces an existing file on Linux, macOS and
 * Android, but on Windows it fails when the target exists, so PGPony Desktop
 * saved the first PIN and then failed every later save (the wrong PIN count,
 * the duress PIN, a new PIN). An atomic move replaces the target on every
 * platform. A file another program holds open for a moment on Windows (a
 * virus scanner, an indexer) can still refuse it, so it is tried a few times.
 */
internal fun writeFileAtomically(target: File, text: String) {
    val dir = target.parentFile ?: throw IOException("no directory for ${target.name}")
    val tmp = File(dir, "${target.name}.tmp")
    FileOutputStream(tmp).use { out ->
        out.write(text.toByteArray(Charsets.UTF_8))
        out.flush()
        out.fd.sync()
    }
    var lastError: Exception? = null
    for (attempt in 1..5) {
        try {
            Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            lastError = null
            break
        } catch (e: java.nio.file.AtomicMoveNotSupportedException) {
            lastError = e
            break
        } catch (e: IOException) {
            lastError = e
            Thread.sleep(20L * attempt)
        }
    }
    if (lastError != null) {
        tmp.delete()
        throw IOException("could not replace ${target.name}", lastError)
    }
    // The rename itself reaches the disk once the directory is synced. Not
    // every filesystem allows opening a directory; the file is in place either way.
    runCatching { FileChannel.open(dir.toPath(), StandardOpenOption.READ).use { it.force(true) } }
}

/**
 * The app lock file (filesDir/app_lock). A plain file read on every use, like
 * SessionPolicy's, so the main and :remote_api processes never hold two copies.
 *
 * Beside it, a marker (filesDir/app_lock_on) says PIN mode is on. It is written
 * before the first config and removed only by [clear] (the switch back to
 * device unlock after a verified PIN, or the app reset), first, before the
 * config. So a config that is missing or unreadable while the marker exists
 * reads as "locked, unavailable", never as "no lock".
 */
class AppLockFileStore(private val dir: File) {
    private val file: File get() = File(dir, FILE_NAME)
    private val marker: File get() = File(dir, MARKER_NAME)

    /** PIN mode is on: the marker, or a config, exists. */
    fun isOn(): Boolean = marker.isFile || file.isFile

    fun load(): AppLockConfig? = try {
        val f = file
        if (f.isFile) AppLockCodec.decode(f.readText()) else null
    } catch (_: Exception) {
        null
    }

    /** Mark PIN mode on. Call before the first [save]. */
    fun markOn() {
        if (!dir.exists()) dir.mkdirs()
        writeFileAtomically(marker, "1\n")
    }

    fun save(config: AppLockConfig) {
        if (!dir.exists()) dir.mkdirs()
        writeFileAtomically(file, AppLockCodec.encode(config))
    }

    /** Leave PIN mode: the marker goes first, so an interrupted clear still reads the config. */
    fun clear() {
        marker.delete()
        File(dir, FILE_NAME).delete()
        File(dir, "$FILE_NAME.tmp").delete()
        File(dir, "$MARKER_NAME.tmp").delete()
    }

    companion object {
        const val FILE_NAME = "app_lock"
        const val MARKER_NAME = "app_lock_on"
    }
}

/**
 * The wipe's resume flag (filesDir/wipe_pending). Written and synced before
 * anything else is touched, removed only after a full pass, so a wipe the
 * system cut short finishes on the next start.
 */
class WipeFlag(private val dir: File) {
    private val file: File get() = File(dir, FILE_NAME)

    fun isPending(): Boolean = file.exists()

    fun markPending() {
        if (!dir.exists()) dir.mkdirs()
        FileOutputStream(file).use { out ->
            out.write(1)
            out.flush()
            runCatching { out.fd.sync() }
        }
    }

    fun clear() {
        file.delete()
    }

    companion object {
        const val FILE_NAME = "wipe_pending"
    }
}
