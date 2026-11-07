// SecureSshKeyVault.kt
// PGPony Android, 4.8.0 RC7 (item 1): the app's SshKeyVault, backed by
// SecureKeyStore, so SSH seeds are protected exactly like OpenPGP secret keys
// (per-key AES-256-GCM data key under the hardware Keystore key, files under
// filesDir/secure_keystore_v2, safe across the app and :remote_api processes).
//
// Why not a Room table: the OpenPGP keyring keeps metadata in Room and material
// in SecureKeyStore, but an SSH key's metadata is three fields that are only
// ever read together with the key. Keeping both in SecureKeyStore needs no
// schema bump or migration, keeps the label sealed too, and is covered by the
// existing Clear All Data and duress paths (cryptoErase, wipeAll) with no new
// table to remember.

package com.pgpony.android.data.ssh

import com.pgpony.android.data.SecureKeyStore

class SecureSshKeyVault(private val store: SecureKeyStore) : SshKeyVault {
    override fun names(): List<String> = store.sshKeyNames()
    override fun readSecret(name: String): ByteArray? = store.loadSshSecret(name)
    override fun readMeta(name: String): ByteArray? = store.loadSshMeta(name)
    override fun write(name: String, secret: ByteArray, meta: ByteArray) = store.storeSshKey(name, secret, meta)
    override fun writeMeta(name: String, meta: ByteArray) = store.storeSshMeta(name, meta)
    override fun delete(name: String) = store.deleteSshKey(name)
    override fun deleteAll() = store.deleteAllSshKeys()
}
