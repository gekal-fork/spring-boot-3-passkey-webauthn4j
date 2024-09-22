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
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.credential.CredentialRecordImpl
import com.webauthn4j.data.AttestationConveyancePreference
import com.webauthn4j.data.AuthenticationData
import com.webauthn4j.data.AuthenticationParameters
import com.webauthn4j.data.AuthenticationRequest
import com.webauthn4j.data.AuthenticatorAttachment
import com.webauthn4j.data.AuthenticatorSelectionCriteria
import com.webauthn4j.data.PublicKeyCredentialCreationOptions
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialHints
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialRequestOptions
import com.webauthn4j.data.PublicKeyCredentialRpEntity
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.data.RegistrationData
import com.webauthn4j.data.RegistrationParameters
import com.webauthn4j.data.RegistrationRequest
import com.webauthn4j.data.UserVerificationRequirement
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs
import com.webauthn4j.data.extension.client.ExtensionClientOutput
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.verifier.exception.VerificationException
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

    private val rp = PublicKeyCredentialRpEntity(
        // id: 自サイトのIDを指定する。通常はドメイン名を設定する
        "localhost",
        // name: 自サイトの名前を指定する
        "webauthn4j-test"
    )

    // origin: 自サイトのオリジンを指定する、ここで許可されたオリジンからのリクエストのみ受け付ける
    private val origin = Origin.create("http://localhost:8080")

    override fun getRegisterOption(userId: String): RegisterOption {
        val mUser = mUserRepository.findByUserId(userId) ?: throw RuntimeException("User not found")

        val challenge = DefaultChallenge()

        val userInfo = PublicKeyCredentialUserEntity(
            createUserId(mUser.internalId),     // id
            userId,                             // name
            mUser.displayName,                  // displayName
        )

        // PublicKeyCredentialParameters の指定はどうするのがいいのか今ひとつわからないんですけど、
        // WEB+DB PRESS Vol.136 第3章 パスキー実装の基礎知識 のサンプルの通りに指定した
        // https://gihyo.jp/magazine/wdpress/archive/2023/vol136
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

        // このユーザーで登録済みのクレデンシャルを設定する
        val excludeCredentials = mFidoCredentialRepository.findByUserInternalId(mUser.internalId).map { credential ->
            PublicKeyCredentialDescriptor(
                PublicKeyCredentialType.PUBLIC_KEY,
                credential.credentialId,
                null
            )
        }

        val authenticatorSelectionCriteria = AuthenticatorSelectionCriteria(
            // authenticatorAttachment: 認証器の種類を指定する。とくにこだわらないので何でもヨシのnull
//            AuthenticatorAttachment.PLATFORM,
//            AuthenticatorAttachment.CROSS_PLATFORM,
            null,
            // requireResidentKey: パスキーとして登録する場合は true を指定すること
            true,
            // パスキーとして登録する場合は REQUIRED を指定すること
            UserVerificationRequirement.REQUIRED
        )

        // 登録結果(attestation)に署名をつけるかどうかを指定する。
        // NONE: 署名無しを指定する
        // 署名が付く場合、attestationStatementに署名、formatに署名形式が含まれる
        // 署名形式は packed, tpm, android-key など種類があって検証方法も異なるが、ここではNONE指定なので深く考えないことにする
        val attestation = AttestationConveyancePreference.NONE

//        val hints = listOf(
//            PublicKeyCredentialHints.create("hybrid"),
//            PublicKeyCredentialHints.create("client-device"),
//            PublicKeyCredentialHints.create("security-key"),
//            )
        val hints = null

        val option = PublicKeyCredentialCreationOptions(
            rp,
            userInfo,
            challenge,
            pubKeyCredParams,
            TimeUnit.SECONDS.toMillis(60),
            excludeCredentials,
            authenticatorSelectionCriteria,
            hints,
            attestation,
            // extensions: 拡張機能は使わないので null を指定する
            null
        )

        return RegisterOption(option)

    }

    override fun verifyRegisterAttestation(
        registerOption: RegisterOption,
        publicKeyCredentialCreateResultJson: String,
    ): AttestationVerifyResult {

        val registrationData = createRegistrationData(publicKeyCredentialCreateResultJson)
        val registrationParameters = createRegistrationParameters(registerOption)

        try {
            WebAuthnManager.createNonStrictWebAuthnManager().verify(registrationData, registrationParameters)
        } catch (e: VerificationException) {
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

    private fun createRegistrationData(publicKeyCredentialCreateResultJson: String): RegistrationData {
        val pkc = PublicKeyCredentialCreateResultBuilder.build(publicKeyCredentialCreateResultJson)
        if (pkc.response == null) {
            throw RuntimeException("response is null")
        }

        val decoder = Base64.getUrlDecoder()
        val attestationObject = decoder.decode(pkc.response.attestationObject)
        val clientDataJSON = decoder.decode(pkc.response.clientDataJSON)

        val registrationRequest = RegistrationRequest(
            attestationObject,
            clientDataJSON,
            // clientExtensionsJSON: 登録オプションでExtensionは何も指定してないのでこちらも未指定にする
            null,
            pkc.response.transports
        )

        val registrationData = try {
            WebAuthnManager.createNonStrictWebAuthnManager().parse(registrationRequest)
        } catch (e: DataConversionException) {
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw e
        }

        return registrationData
    }

    private fun createRegistrationParameters(registerOption: RegisterOption): RegistrationParameters {
        // 最初に送ったチャレンジ
        val challenge = DefaultChallenge(registerOption.publicKeyCredentialCreationOptions.challenge.toString())

        val serverProperty = ServerProperty(
            origin,
            rp.id!!,
            challenge,
            // tokenBindingId: Token Binding ID による検証は行わないので null を指定する
            null
        )

        // RPが希望する公開鍵のアルゴリズムを指定する
        // ここで指定されたアルゴリズム以外で署名されている場合は NotAllowedAlgorithmException が発生する
        // 今回は何でもOKなので null を指定する
        val pubKeyCredParams = null

        // ユーザーがちゃんと認証を行ったかどうかを指定する
        // パスキーの場合はtrueを指定すること
        // val userVerificationRequired = true
        // val userPresenceRequired = true

        // Automatic Passkey Upgrades のときは UV, UP のチェックをしない
        val userVerificationRequired = false
        val userPresenceRequired = false

        val registrationParameters = RegistrationParameters(
            serverProperty,
            pubKeyCredParams,
            userVerificationRequired,
            userPresenceRequired,
        )

        return registrationParameters
    }

    override fun getAuthenticateOption(): AuthenticateOption {
        // チャレンジを生成する
        val challenge = DefaultChallenge()

        return AuthenticateOption(
            PublicKeyCredentialRequestOptions(
                challenge,
                TimeUnit.SECONDS.toMillis(60),
                rp.id,
                // allowCredentials: 認証時に指定するクレデンシャル、パスキーの場合は null を指定する
                null,
                // userVerification: パスキーの場合は REQUIRED を指定する
                UserVerificationRequirement.REQUIRED,
                // extensions: 拡張機能は使わないので null を指定する
                null
            )
        )
    }

    override fun verifyAuthenticateAssertion(
        authenticateOption: AuthenticateOption,
        publicKeyCredentialGetResultJson: String,
    ): AssertionVerifyResult {

        val authenticationData = createAuthenticationData(publicKeyCredentialGetResultJson)

        // credentialRecord
        val userInternalId = String(authenticationData.userHandle!!)
        val (credentialRecord, userId) = mFidoCredentialService.load(userInternalId, authenticationData.credentialId!!)
        if (credentialRecord == null || userId.isNullOrEmpty()) {
            return AssertionVerifyResult(false, "")
        }

        val authenticationParameters = createAuthenticationParameters(authenticateOption, credentialRecord)

        try {
            WebAuthnManager.createNonStrictWebAuthnManager().verify(authenticationData, authenticationParameters)
        } catch (e: VerificationException) {
            // If you would like to handle WebAuthn data validation error, please catch ValidationException
            throw e
        }

        return AssertionVerifyResult(true, userId)
    }

    private fun createAuthenticationData(publicKeyCredentialGetResultJson: String): AuthenticationData {
        val pkc = PublicKeyCredentialGetResultBuilder.build(publicKeyCredentialGetResultJson)

        val decoder = Base64.getUrlDecoder()
        val credentialId = decoder.decode(pkc.id)
        val userHandle = decoder.decode(pkc.response!!.userHandle)
        val authenticatorData = decoder.decode(pkc.response.authenticatorData)
        val clientDataJSON = decoder.decode(pkc.response.clientDataJSON)
        val signature = decoder.decode(pkc.response.signature)

        val authenticationRequest = AuthenticationRequest(
            credentialId,
            userHandle,
            authenticatorData,
            clientDataJSON,
            // clientExtensionsJSON: 拡張機能は使わないので null を指定する
            null,
            signature,
        )

        val authenticationData = try {
            WebAuthnManager.createNonStrictWebAuthnManager().parse(authenticationRequest)
        } catch (e: DataConversionException) {
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw e
        }

        return authenticationData
    }

    private fun createAuthenticationParameters(
        authenticateOption: AuthenticateOption,
        credentialRecord: CredentialRecord,
    ): AuthenticationParameters {
        // 最初に送ったチャレンジ
        val challenge = DefaultChallenge(authenticateOption.publicKeyCredentialRequestOptions.challenge.toString())

        val serverProperty = ServerProperty(
            origin,
            rp.id!!,
            challenge,
            // tokenBindingId: Token Binding ID による検証は行わないので null を指定する
            null
        )

        val authenticationParameters = AuthenticationParameters(
            serverProperty,
            credentialRecord,
            // allowCredentials: 認証時に指定するクレデンシャル、パスキーの場合は null を指定する
            null,
            // userVerificationRequired: パスキーの場合は true を指定する
            true,
            // userPresenceRequired: パスキーの場合は true を指定する
            true
        )

        return authenticationParameters
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
