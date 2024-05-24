package com.example.springwebauthn4j

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher


class Fido2AuthenticationFilter(
    pattern: String,
    httpMethod: String,
) : AbstractAuthenticationProcessingFilter(AntPathRequestMatcher(pattern, httpMethod)) {
    override fun attemptAuthentication(request: HttpServletRequest?, response: HttpServletResponse?): Authentication {
        if (request!!.method != "POST") {
            throw AuthenticationServiceException("Authentication method not supported: " + request.method)
        }

        val assertion = obtainAssertion(request)
        val principal = obtainPrincipal(request)

        val credentials = AssertionAuthenticationToken.Fido2Credentials(assertion)

        val authorities = principal.authorities.map {
            SimpleGrantedAuthority(it.authority)
        }

        val authRequest = AssertionAuthenticationToken(principal, credentials, authorities)
        setDetails(request, authRequest)
        return authenticationManager.authenticate(authRequest)
    }

    private fun obtainAssertion(request: HttpServletRequest): String {
        val json = request.getParameter("assertion")
        if (json.isNullOrEmpty()) {
            throw AuthenticationServiceException("assertion")
        }
        return json
    }

    private fun obtainPrincipal(request: HttpServletRequest): User {
        val session = request.session
        val securityContext = session.getAttribute("SPRING_SECURITY_CONTEXT") as? SecurityContext
            ?: return User("<dmy>","",emptyList())
        val principal = securityContext.authentication.principal
        if (principal !is User) {
            throw AuthenticationServiceException("assertion")
        }
        return principal
    }

    private fun setDetails(request: HttpServletRequest?, authRequest: AssertionAuthenticationToken) {
        authRequest.details = authenticationDetailsSource.buildDetails(request)
    }
}
