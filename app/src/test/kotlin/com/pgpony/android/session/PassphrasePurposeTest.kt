// PassphrasePurposeTest.kt
// PGPony Android 4.6.3 (#15): the provider passphrase prompt names the
// operation the client asked for instead of always saying "sign".

package com.pgpony.android.session

import com.pgpony.android.provider.PassphrasePurpose
import com.pgpony.android.provider.SshAuthenticationService
import org.junit.Assert.assertEquals
import org.junit.Test
import org.openintents.openpgp.util.OpenPgpApi

class PassphrasePurposeTest {

    @Test
    fun decryptRequests_askToDecrypt() {
        assertEquals(PassphrasePurpose.DECRYPT, PassphrasePurpose.of(OpenPgpApi.ACTION_DECRYPT_VERIFY))
        assertEquals(PassphrasePurpose.DECRYPT, PassphrasePurpose.of(OpenPgpApi.ACTION_DECRYPT_METADATA))
    }

    @Test
    fun sshRequests_askToSignIn() {
        assertEquals(PassphrasePurpose.SSH, PassphrasePurpose.of(SshAuthenticationService.ACTION_SIGN))
    }

    @Test
    fun everythingElse_asksToSign() {
        assertEquals(PassphrasePurpose.SIGN, PassphrasePurpose.of(OpenPgpApi.ACTION_SIGN_AND_ENCRYPT))
        assertEquals(PassphrasePurpose.SIGN, PassphrasePurpose.of(OpenPgpApi.ACTION_CLEARTEXT_SIGN))
        assertEquals(PassphrasePurpose.SIGN, PassphrasePurpose.of(null))
    }
}
