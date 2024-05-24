package com.example.springwebauthn4j

import com.example.springwebauthn4j.service.AuthenticateOption
import com.example.springwebauthn4j.service.WebAuthnServerService
import com.example.springwebauthn4j.util.SecurityContextUtil
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.stereotype.Component


@Component
class Fido2AuthenticationProvider(
    private val webAuthnServerService: WebAuthnServerService,
    private val request: HttpServletRequest?
) : AuthenticationProvider {

    override fun authenticate(authentication: Authentication): Authentication {
        val userName = if (authentication is AssertionAuthenticationToken) {

            val authenticateOption = request?.session?.getAttribute("authenticateOption") as? AuthenticateOption
                ?: throw BadCredentialsException("authenticateOption not found")

            val publicKeyCredentialGetResultJson = authentication.credentials.publicKeyCredentialGetResultJson
            if (publicKeyCredentialGetResultJson.isEmpty()) {
                throw BadCredentialsException("Invalid Assertion")
            }

            val verifyResult = try {
                webAuthnServerService.verifyAuthenticateAssertion(
                    authenticateOption,
                    publicKeyCredentialGetResultJson
                )
            } catch (e: Exception) {
                throw BadCredentialsException("Invalid Assertion")
            }
            if (!verifyResult.isSuccess) {
                throw BadCredentialsException("Assertion Verify Failed")
            }

            verifyResult.userId
        } else {
            throw BadCredentialsException("Invalid Authentication")
        }

        // set Authenticated
        val authorities = listOf(
            SimpleGrantedAuthority(SecurityContextUtil.Auth.AUTHENTICATED_FIDO.value),
            SimpleGrantedAuthority(SecurityContextUtil.Role.USER.value)
        )

        val authenticatedPrincipal = User(userName, "", authorities)

        val result = AssertionAuthenticationToken(authenticatedPrincipal, authentication.credentials, authorities)
        result.isAuthenticated = true
        return result
    }

    override fun supports(authentication: Class<*>): Boolean {
        return AssertionAuthenticationToken::class.java.isAssignableFrom(authentication)
    }
}
