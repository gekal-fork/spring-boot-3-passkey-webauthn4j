package com.example.springwebauthn4j

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User


class AssertionAuthenticationToken(
    val principal: User,
    val credentials: Fido2Credentials,
    authorities: Collection<SimpleGrantedAuthority>,
) : AbstractAuthenticationToken(authorities) {
    override fun getPrincipal(): Any {
        return principal
    }

    override fun getCredentials(): Any {
        return credentials
    }

    class Fido2Credentials(
        val publicKeyCredentialGetResultJson: String,
    )
}
