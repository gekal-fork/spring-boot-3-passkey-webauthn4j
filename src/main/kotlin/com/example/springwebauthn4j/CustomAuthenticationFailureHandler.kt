package com.example.springwebauthn4j

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler


class CustomAuthenticationFailureHandler(defaultFailureUrl: String) :
    SimpleUrlAuthenticationFailureHandler(defaultFailureUrl) {

    override fun onAuthenticationFailure(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        exception: AuthenticationException?
    ) {
        SecurityContextHolder.clearContext()

        val session = request?.getSession(false)
        session?.invalidate()

        super.onAuthenticationFailure(request, response, exception)
    }
}
