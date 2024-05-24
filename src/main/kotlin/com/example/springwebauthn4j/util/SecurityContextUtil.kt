package com.example.springwebauthn4j.util

import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User

class SecurityContextUtil {

    enum class Auth(val value: String) {
        AUTHENTICATED_USERNAME("authenticated-username"),
        AUTHENTICATED_PASSWORD("authenticated-password"),
        AUTHENTICATED_FIDO("authenticated-fido"),
    }

    enum class Role(val value: String) {
        USER("ROLE_USER")
    }

    companion object {
        fun getLoginUser(): User? {
            val principal = SecurityContextHolder.getContext()?.authentication?.principal
            return if (principal is User) {
                principal
            } else {
                null
            }
        }

        fun isUsernameAuthenticated(): Boolean {
            val user = getLoginUser()
            return if (user != null) {
                val retVal = user.authorities?.any {
                    it.authority == Auth.AUTHENTICATED_USERNAME.value
                } ?: false

                retVal
            } else {
                false
            }
        }
    }
}
