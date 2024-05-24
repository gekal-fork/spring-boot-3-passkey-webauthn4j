package com.example.springwebauthn4j.service.webauthn4j

import com.example.springwebauthn4j.repository.MfidoCredentialRepository
import com.example.springwebauthn4j.repository.MfidoCredentialforWebAuthn4J
import com.example.springwebauthn4j.repository.MuserRepository
import com.example.springwebauthn4j.service.AttestationVerifyResult
import com.example.springwebauthn4j.service.FidoCredentialService
import com.webauthn4j.converter.AttestedCredentialDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.credential.CredentialRecordImpl
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput
import org.springframework.stereotype.Service


@Service
class WebAuthn4JCredentialServiceImpl(
    private val mUserRepository: MuserRepository,
    private val mFidoCredentialRepository: MfidoCredentialRepository,
) : FidoCredentialService {
    override fun save(userId: String, attestationVerifyResult: AttestationVerifyResult) {
        val mUser = mUserRepository.findByUserId(userId) ?: throw RuntimeException("User not found")

        // serialize
        val objectConverter = ObjectConverter()
        val attestedCredentialDataConverter = AttestedCredentialDataConverter(objectConverter)
        val serializedAttestedCredentialData =
            attestedCredentialDataConverter.convert(attestationVerifyResult.credentialRecord.attestedCredentialData)

//        val attestationStatementEnvelope = AttestationStatementEnvelope(credentialRecord.attestationStatement)
        val attestationStatementEnvelope = AttestationStatementEnvelope()
        // TODO attestationStatement は NoneAttestationStatement
        attestationStatementEnvelope.AttestationStatementEnvelope(attestationVerifyResult.credentialRecord.attestationStatement)

//
//        val serializedEnvelope = objectConverter.cborConverter.writeValueAsBytes(attestationStatementEnvelope)

//        val serializedTransports = objectConverter.jsonConverter.writeValueAsString(authenticator.transports)
//        val serializedAuthenticatorExtensions =
//            objectConverter.cborConverter.writeValueAsBytes(authenticator.authenticatorExtensions)
//        val serializedClientExtensions =
//            objectConverter.jsonConverter.writeValueAsString(authenticator.clientExtensions)

        // save
//        entityManager.persist(
//            Credentials(
//                Base64UrlUtil.encodeToString(credentialId),
//                serializedAttestedCredentialData,
//                serializedEnvelope,
//                serializedTransports,
//                serializedAuthenticatorExtensions,
//                serializedClientExtensions,
//                authenticator.counter
//            )
//        )

        val entity = MfidoCredentialforWebAuthn4J(0, attestationVerifyResult.credentialId, mUser.internalId, serializedAttestedCredentialData)
        mFidoCredentialRepository.save(entity)
    }

    override fun load(userInternalId: String, credentialId: ByteArray): Pair<CredentialRecord?,String?> {
        val entityList = mFidoCredentialRepository.findByUserInternalId(userInternalId)
        val mFidoCredential = entityList.find { it.credentialId.contentEquals(credentialId) } ?: return null to null

        // deserialize
        val objectConverter = ObjectConverter()
        val attestedCredentialDataConverter = AttestedCredentialDataConverter(objectConverter)
        val deserializedAttestedCredentialData = attestedCredentialDataConverter.convert(mFidoCredential.ateestedCredentialData)

        // TODO ???
        val attestationStatement = NoneAttestationStatement()
        val authenticatorExtensions =
            AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput>()

        val credentialRecord = CredentialRecordImpl(
            attestationStatement,
            null,
            null,
            null,
            0,      // counter
            deserializedAttestedCredentialData,
            authenticatorExtensions,
            null,
            null,
            null
        )

        val mUser = mUserRepository.findByInternalId(mFidoCredential.userInternalId) ?: return null to null

        return credentialRecord to mUser.userId
    }

}
