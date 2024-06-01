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

        val entity = MfidoCredentialforWebAuthn4J(
            0,
            mUser.internalId,
            attestationVerifyResult.credentialId,
            attestationVerifyResult.credentialRecord.counter,
            serializedAttestedCredentialData
        )

        mFidoCredentialRepository.save(entity)
    }

    override fun load(userInternalId: String, credentialId: ByteArray): Pair<CredentialRecord?,String?> {
        val entityList = mFidoCredentialRepository.findByUserInternalId(userInternalId)
        val mFidoCredential = entityList.find { it.credentialId.contentEquals(credentialId) } ?: return null to null

        val mUser = mUserRepository.findByInternalId(mFidoCredential.userInternalId) ?: return null to null

        // deserialize
        val objectConverter = ObjectConverter()
        val attestedCredentialDataConverter = AttestedCredentialDataConverter(objectConverter)
        val deserializedAttestedCredentialData = attestedCredentialDataConverter.convert(mFidoCredential.ateestedCredentialData)

        val credentialRecord = CredentialRecordImpl(
            NoneAttestationStatement(),
            null,
            null,
            null,
            mFidoCredential.signCount,
            deserializedAttestedCredentialData,
            AuthenticationExtensionsAuthenticatorOutputs(),
            null,
            null,
            null
        )

        return credentialRecord to mUser.userId
    }

}
