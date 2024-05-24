package com.example.springwebauthn4j.service.webauthn4j

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.webauthn4j.data.attestation.statement.AttestationStatement


class AttestationStatementEnvelope {

    @JsonProperty("attStmt")
    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.EXTERNAL_PROPERTY, property = "fmt")
    private var attestationStatement: AttestationStatement? = null

    @JsonCreator
    fun AttestationStatementEnvelope(@JsonProperty("attStmt") attestationStatement: AttestationStatement?) {
        this.attestationStatement = attestationStatement
    }

    @JsonProperty("fmt")
    fun getFormat(): String? {
        return attestationStatement?.format
    }

    fun getAttestationStatement(): AttestationStatement? {
        return attestationStatement
    }
}
