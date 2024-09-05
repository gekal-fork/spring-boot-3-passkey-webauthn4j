package com.example.springwebauthn4j.controller

import com.example.springwebauthn4j.service.RegisterOption
import com.example.springwebauthn4j.service.Status
import com.webauthn4j.data.AttestationConveyancePreference
import com.webauthn4j.data.AuthenticatorSelectionCriteria
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialHints
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialRpEntity
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput

class ServerPublicKeyCredentialCreationOptionsResponse(
    val rp: PublicKeyCredentialRpEntity?,
    val user: PublicKeyCredentialUserEntity?,
    val attestation: AttestationConveyancePreference?,
    val authenticatorSelection: AuthenticatorSelectionCriteria?,
    val challenge: String?,
    val excludeCredentials: List<PublicKeyCredentialDescriptor>?,
    val pubKeyCredParams: List<PublicKeyCredentialParameters>?,
    val timeout: Long?,
    val extensions: AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput>?,
    val hints: List<PublicKeyCredentialHints>?,
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
        null,
        null,
        null,
        null,
    ) {
        this.status = status
        this.errorMessage = errorMessage
    }

    constructor(
        registerOption: RegisterOption,
    ) : this(
        registerOption.publicKeyCredentialCreationOptions.rp,
        registerOption.publicKeyCredentialCreationOptions.user,
        registerOption.publicKeyCredentialCreationOptions.attestation,
        registerOption.publicKeyCredentialCreationOptions.authenticatorSelection,
        registerOption.publicKeyCredentialCreationOptions.challenge.toString(),
        registerOption.publicKeyCredentialCreationOptions.excludeCredentials,
        registerOption.publicKeyCredentialCreationOptions.pubKeyCredParams,
        registerOption.publicKeyCredentialCreationOptions.timeout,
        registerOption.publicKeyCredentialCreationOptions.extensions,
        registerOption.publicKeyCredentialCreationOptions.hints,
    )
}
