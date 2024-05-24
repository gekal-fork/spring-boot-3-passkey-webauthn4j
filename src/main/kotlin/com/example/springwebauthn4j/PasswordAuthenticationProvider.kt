package com.example.springwebauthn4j

import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.stereotype.Component

@Component
class PasswordAuthenticationProvider: DaoAuthenticationProvider() {
    override fun doAfterPropertiesSet() {}
}
