package com.example.springwebauthn4j.controller

import com.example.springwebauthn4j.service.FidoCredentialService
import com.example.springwebauthn4j.service.RegisterOption
import com.example.springwebauthn4j.service.Status
import com.example.springwebauthn4j.service.WebAuthnServerService
import com.example.springwebauthn4j.util.SecurityContextUtil
import jakarta.servlet.http.HttpSession
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController


@RestController
class Fido2RestController(
    private val webAuthnServerService: WebAuthnServerService,
    private val fidoCredentialService: FidoCredentialService,
) {
    @PostMapping("/register/option")
    fun registerOption(
        session: HttpSession
    ): ServerPublicKeyCredentialCreationOptionsResponse {
        val user = SecurityContextUtil.getLoginUser() ?: return ServerPublicKeyCredentialCreationOptionsResponse(
            Status.FAILED,
            "user not found"
        )

        return try {
            val registerOption = webAuthnServerService.getRegisterOption(user.username)
            session.setAttribute("registerOption", registerOption)

            return ServerPublicKeyCredentialCreationOptionsResponse(registerOption)
        } catch (e: Exception) {
            ServerPublicKeyCredentialCreationOptionsResponse(Status.FAILED, e.message ?: "")
        }
    }

    @PostMapping("/register/verify")
    fun registerVerify(
        @RequestBody publicKeyCredentialCreateResultJson: String,
        session: HttpSession
    ): ServerResponse {
        val registerOption = session.getAttribute("registerOption") as? RegisterOption
            ?: return ServerResponse(Status.FAILED, "registerOption not found")

        val user = SecurityContextUtil.getLoginUser() ?: return ServerPublicKeyCredentialCreationOptionsResponse(
            Status.FAILED,
            "user not found"
        )

        return try {
            val attestationVerifyResult = webAuthnServerService.verifyRegisterAttestation(
                registerOption,
                publicKeyCredentialCreateResultJson,
            )

            fidoCredentialService.save(user.username, attestationVerifyResult)

            ServerResponse(Status.OK, "")
        } catch (e: Exception) {
            ServerResponse(Status.FAILED, e.message ?: "")
        }
    }

    @PostMapping("/authenticate/option")
    fun authenticateOption(
        session: HttpSession
    ): ServerPublicKeyCredentialGetOptionsResponse {
        return try {
            val authenticateOption = webAuthnServerService.getAuthenticateOption()
            session.setAttribute("authenticateOption", authenticateOption)

            return ServerPublicKeyCredentialGetOptionsResponse(authenticateOption)
        } catch (e: Exception) {
            ServerPublicKeyCredentialGetOptionsResponse(Status.FAILED, e.message ?: "")
        }
    }
}
