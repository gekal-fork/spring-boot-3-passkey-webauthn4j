package com.example.springwebauthn4j.service

import com.webauthn4j.credential.CredentialRecord

class AttestationVerifyResult(
    val credentialId: ByteArray,
    val credentialRecord: CredentialRecord
)
