package com.example.springwebauthn4j.repository

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table

/**
 * SpringBootとJPAを使ったEntityクラス
 * @Entity：Entityクラスであることを宣言する
 * @Table：name属性で連携するテーブル名を指定する
 */
@Entity
@Table(name = "M_FIDO_CREDENTIAL_FOR_WEBAUTHN4J")
data class MfidoCredentialforWebAuthn4J(
    /**
     *  @Id：主キーに指定する。※複合キーの場合は@EmbeddedIdを使用
     *  @GeneratedValue：主キーの指定をJPAに委ねる
     *  @Column：name属性でマッピングするカラム名を指定する
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="ID")
    var id: Int,

    @Column(name="CREDENTIAL_ID")
    var credentialId: ByteArray,

    @Column(name="USER_INTERNAL_ID")
    var userInternalId: String,

    @Column(name="ATTESTED_CREDENTIAL_DATA")
    var ateestedCredentialData: ByteArray,
)
