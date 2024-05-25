package com.example.springwebauthn4j.service.webauthn4j

import com.example.springwebauthn4j.repository.MfidoCredentialRepository
import com.example.springwebauthn4j.repository.MuserRepository
import com.example.springwebauthn4j.service.AssertionVerifyResult
import com.example.springwebauthn4j.service.AttestationVerifyResult
import com.example.springwebauthn4j.service.AuthenticateOption
import com.example.springwebauthn4j.service.FidoCredentialService
import com.example.springwebauthn4j.service.RegisterOption
import com.example.springwebauthn4j.service.WebAuthnServerService
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.converter.exception.DataConversionException
import com.webauthn4j.credential.CredentialRecordImpl
import com.webauthn4j.data.AttestationConveyancePreference
import com.webauthn4j.data.AuthenticationParameters
import com.webauthn4j.data.AuthenticationRequest
import com.webauthn4j.data.AuthenticatorSelectionCriteria
import com.webauthn4j.data.PublicKeyCredentialCreationOptions
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialRequestOptions
import com.webauthn4j.data.PublicKeyCredentialRpEntity
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.data.RegistrationParameters
import com.webauthn4j.data.RegistrationRequest
import com.webauthn4j.data.UserVerificationRequirement
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs
import com.webauthn4j.data.extension.client.ExtensionClientOutput
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.validator.exception.ValidationException
import org.springframework.stereotype.Service
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.concurrent.TimeUnit


@Service
class WebAuthn4JServerServiceImpl(
    private val mUserRepository: MuserRepository,
    private val mFidoCredentialService: FidoCredentialService,
    private val mFidoCredentialRepository: MfidoCredentialRepository,
) : WebAuthnServerService {

    private val rp = PublicKeyCredentialRpEntity("localhost", "webauthn4j-test")
    private val origin = Origin.create("http://localhost:8080")

    override fun getRegisterOption(userId: String): RegisterOption {
        val mUser = mUserRepository.findByUserId(userId) ?: throw RuntimeException("User not found")

        val challenge = DefaultChallenge()

        val userInfo = PublicKeyCredentialUserEntity(
            createUserId(mUser.internalId),     // id
            userId,                             // name
            mUser.displayName,                  // displayName
        )

        val pubKeyCredParams = listOf(
            PublicKeyCredentialParameters(
                PublicKeyCredentialType.PUBLIC_KEY,
                COSEAlgorithmIdentifier.ES256
            ),
            PublicKeyCredentialParameters(
                PublicKeyCredentialType.PUBLIC_KEY,
                COSEAlgorithmIdentifier.RS256
            )
        )

        val excludeCredentials = mFidoCredentialRepository.findByUserInternalId(mUser.internalId).map { credential ->
            PublicKeyCredentialDescriptor(
                PublicKeyCredentialType.PUBLIC_KEY,
                credential.credentialId,
                null
            )
        }

        val authenticatorSelectionCriteria = AuthenticatorSelectionCriteria(
            null,
            true,
            UserVerificationRequirement.REQUIRED
        )

        // https://www.w3.org/TR/webauthn/#enumdef-attestationconveyancepreference
        val attestation = AttestationConveyancePreference.NONE

        return RegisterOption(
            PublicKeyCredentialCreationOptions(
                rp,
                userInfo,
                challenge,
                pubKeyCredParams,
                TimeUnit.SECONDS.toMillis(60),
                excludeCredentials,
                authenticatorSelectionCriteria,
                attestation,
                null
            )
        )

    }

    override fun verifyRegisterAttestation(
        registerOption: RegisterOption,
        publicKeyCredentialCreateResultJson: String,
    ): AttestationVerifyResult {

        val pkc = PublicKeyCredentialCreateResultBuilder.build(publicKeyCredentialCreateResultJson)

        // Client properties
        val clientExtensionJSON: String? = null /* set clientExtensionJSON */
        val transports = pkc.response!!.transports

        // Server properties
        val decoder = Base64.getUrlDecoder()
        val attestationObject = decoder.decode(pkc.response.attestationObject)
        val clientDataJSON = decoder.decode(pkc.response.clientDataJSON)

        val challenge = DefaultChallenge(registerOption.publicKeyCredentialCreationOptions.challenge.toString())
        val tokenBindingId: ByteArray? = null /* set tokenBindingId */
        val serverProperty = ServerProperty(origin, rp.id!!, challenge, tokenBindingId)

        // expectations
        val pubKeyCredParams: List<PublicKeyCredentialParameters>? = null
        val userVerificationRequired = false
        val userPresenceRequired = true

        val registrationRequest = RegistrationRequest(
            attestationObject,
            clientDataJSON,
            clientExtensionJSON,
            transports
        )

        val registrationParameters = RegistrationParameters(
            serverProperty,
            pubKeyCredParams,
            userVerificationRequired,
            userPresenceRequired
        )

        val registrationData = try {
            WebAuthnManager.createNonStrictWebAuthnManager().parse(registrationRequest)
        } catch (e: DataConversionException) {
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw e
        }

        try {
            WebAuthnManager.createNonStrictWebAuthnManager().validate(registrationData, registrationParameters)
        } catch (e: ValidationException) {
            // If you would like to handle WebAuthn data validation error, please catch ValidationException
            throw e
        }

        // You may create your own Authenticator implementation to save friendly authenticator name
        val credentialRecord = CredentialRecordImpl(
            registrationData.attestationObject!!,
            registrationData.collectedClientData,
            registrationData.clientExtensions,
            registrationData.transports,
        )

        val credentialId = registrationData.attestationObject!!.authenticatorData.attestedCredentialData!!.credentialId

        return AttestationVerifyResult(credentialId, credentialRecord)
    }

    override fun getAuthenticateOption(): AuthenticateOption {
        val challenge = DefaultChallenge()
        val allowCredentials = null

        return AuthenticateOption(
            PublicKeyCredentialRequestOptions(
                challenge,
                TimeUnit.SECONDS.toMillis(60),
                rp.id,
                allowCredentials,
                UserVerificationRequirement.REQUIRED,
                null
            )
        )
    }

    override fun verifyAuthenticateAssertion(
        authenticateOption: AuthenticateOption,
        publicKeyCredentialGetResultJson: String,
    ): AssertionVerifyResult {

        val pkc = PublicKeyCredentialGetResultBuilder.build(publicKeyCredentialGetResultJson)
        val decoder = Base64.getUrlDecoder()
        val credentialId = decoder.decode(pkc.id)
        val userHandle = decoder.decode(pkc.response!!.userHandle)
        val authenticatorData = decoder.decode(pkc.response.authenticatorData)
        val clientDataJSON = decoder.decode(pkc.response.clientDataJSON)
        val signature: ByteArray = decoder.decode(pkc.response.signature)

        // Client properties
        val clientExtensionJSON: String? = null /* set clientExtensionJSON */

        // Server properties
        val challenge = DefaultChallenge(authenticateOption.publicKeyCredentialRequestOptions.challenge.toString())
        val tokenBindingId: ByteArray? = null /* set tokenBindingId */
        val serverProperty = ServerProperty(origin, rp.id!!, challenge, tokenBindingId)

        // expectations
        val allowCredentials: List<ByteArray>? = null
        val userVerificationRequired = true
        val userPresenceRequired = true

        // credentialRecord
        val userInternalId = String(userHandle)
        val (credentialRecord, userId) = mFidoCredentialService.load(userInternalId, credentialId)
        if (credentialRecord == null || userId.isNullOrEmpty()) {
            return AssertionVerifyResult(false, "")
        }

        val authenticationRequest = AuthenticationRequest(
            credentialId,
            userHandle,
            authenticatorData,
            clientDataJSON,
            clientExtensionJSON,
            signature,
        )

        val authenticationParameters = AuthenticationParameters(
            serverProperty,
            credentialRecord,
            allowCredentials,
            userVerificationRequired,
            userPresenceRequired
        )

        val authenticationData = try {
            WebAuthnManager.createNonStrictWebAuthnManager().parse(authenticationRequest)
        } catch (e: DataConversionException) {
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw e
        }

        try {
            WebAuthnManager.createNonStrictWebAuthnManager().validate(authenticationData, authenticationParameters)
        } catch (e: ValidationException) {
            // If you would like to handle WebAuthn data validation error, please catch ValidationException
            throw e
        }

//        // please update the counter of the authenticator record
//        updateCounter(
//            authenticationData.getCredentialId(),
//            authenticationData.getAuthenticatorData().getSignCount()
//        )

        return AssertionVerifyResult(true, userId)
    }

    private fun createUserId(userId: String): ByteArray {
        return userId.toByteArray(StandardCharsets.UTF_8)
    }

    override fun toUserInternalId(encodedUserHandle: String): String {
        val decoder = Base64.getUrlDecoder()
        val userHandle = decoder.decode(encodedUserHandle)
        return String(userHandle, StandardCharsets.UTF_8)
    }

    class PublicKeyCredentialCreateResultBuilder {
        companion object {
            fun build(publicKeyCredentialCreateResultJson: String): PublicKeyCredentialCreateResult {
                val mapper = jacksonObjectMapper()
                return mapper.readValue(
                    publicKeyCredentialCreateResultJson,
                    PublicKeyCredentialCreateResult::class.java
                )
            }
        }
    }

    class PublicKeyCredentialCreateResult {

        val id: String = ""
        val response: AuthenticatorAttestationResponse? = null
        val clientExtensionResults: AuthenticationExtensionsClientOutputs<ExtensionClientOutput>? = null
        val type: String = ""

        class AuthenticatorAttestationResponse {
            val attestationObject: String = ""
            val clientDataJSON: String = ""
            val transports: Set<String>? = null
        }
    }

    class PublicKeyCredentialGetResultBuilder {
        companion object {
            fun build(publicKeyCredentialGet1ResultJson: String): PublicKeyCredentialGetResult {
                val mapper = jacksonObjectMapper()
                return mapper.readValue(
                    publicKeyCredentialGet1ResultJson,
                    PublicKeyCredentialGetResult::class.java
                )
            }
        }
    }

    class PublicKeyCredentialGetResult {
        val id: String = ""
        val response: AuthenticatorAssertionResponse? = null
        val clientExtensionResults: AuthenticationExtensionsClientOutputs<ExtensionClientOutput>? = null
        val type: String? = null

        class AuthenticatorAssertionResponse {
            val userHandle: String = ""
            val authenticatorData: String = ""
            val clientDataJSON: String = ""
            val signature: String = ""
        }
    }

}
