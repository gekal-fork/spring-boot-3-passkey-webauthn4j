package com.example.springwebauthn4j.service

interface WebAuthnServerService {
    fun getRegisterOption(
        userId: String,
    ): RegisterOption

    fun verifyRegisterAttestation(
        registerOption: RegisterOption,
        publicKeyCredentialCreateResultJson: String,
    ): AttestationVerifyResult

    fun getAuthenticateOption(): AuthenticateOption

    fun verifyAuthenticateAssertion(
        authenticateOption: AuthenticateOption,
        publicKeyCredentialGetResultJson: String,
    ): AssertionVerifyResult

    fun toUserInternalId(encodedUserHandle: String): String
}
