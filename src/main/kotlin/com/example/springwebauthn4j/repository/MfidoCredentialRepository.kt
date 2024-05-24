package com.example.springwebauthn4j.repository

import org.springframework.data.jpa.repository.JpaRepository

interface MfidoCredentialRepository : JpaRepository<MfidoCredentialforWebAuthn4J, Int> {
    fun findByUserInternalId(userInternalId: String): List<MfidoCredentialforWebAuthn4J>
}
