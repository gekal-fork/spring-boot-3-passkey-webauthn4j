package com.example.springwebauthn4j.service

import com.webauthn4j.credential.CredentialRecord

interface FidoCredentialService {
    fun save(userId: String, attestationVerifyResult: AttestationVerifyResult)
    fun load(userInternalId: String, credentialId: ByteArray): Pair<CredentialRecord?,String?>
}
