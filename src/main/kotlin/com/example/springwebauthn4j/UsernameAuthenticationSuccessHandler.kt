package com.example.springwebauthn4j

import com.example.springwebauthn4j.util.SecurityContextUtil
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler

class UsernameAuthenticationSuccessHandler(
    private val nextAuthUrl: String,
    defaultTargetUrl: String
) : SimpleUrlAuthenticationSuccessHandler(defaultTargetUrl) {
    override fun onAuthenticationSuccess(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        authentication: Authentication
    ) {
        if (SecurityContextUtil.isUsernameAuthenticated()) {
            response?.sendRedirect(nextAuthUrl)
        } else {
            super.onAuthenticationSuccess(request, response, authentication)
        }
    }
}
