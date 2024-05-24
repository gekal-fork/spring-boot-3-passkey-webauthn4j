package com.example.springwebauthn4j.controller

import com.example.springwebauthn4j.service.AuthenticateOption
import com.example.springwebauthn4j.service.Status
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.UserVerificationRequirement
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs

class ServerPublicKeyCredentialGetOptionsResponse(
    val challenge: String?,
    val timeout: Long?,
    val rpId: String?,
    val allowCredentials: List<PublicKeyCredentialDescriptor>?,
    val userVerification: UserVerificationRequirement?,
    val extensions: AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput>?,
) : ServerResponse(Status.OK, "") {
    constructor(
        status: Status,
        errorMessage: String,
    ) : this(
        null,
        null,
        null,
        null,
        null,
        null,
    ) {
        this.status = status
        this.errorMessage = errorMessage
    }

    constructor(
        authenticateOption: AuthenticateOption,
    ) : this(
        authenticateOption.publicKeyCredentialRequestOptions.challenge.toString(),
        authenticateOption.publicKeyCredentialRequestOptions.timeout,
        authenticateOption.publicKeyCredentialRequestOptions.rpId,
        authenticateOption.publicKeyCredentialRequestOptions.allowCredentials,
        authenticateOption.publicKeyCredentialRequestOptions.userVerification,
        authenticateOption.publicKeyCredentialRequestOptions.extensions
    )
}
