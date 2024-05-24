package com.example.springwebauthn4j.repository

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table

// @Entity がついた data class は起動時にJPAによってスキャンされる
// スキャンする対象は @SpringBootApplication パッケージか、@EntityScanで設定されたパッケージ
// それ以外の場所においてもスキャンされないので注意

/**
 * SpringBootとJPAを使ったEntityクラス
 * @Entity：Entityクラスであることを宣言する
 * @Table：name属性で連携するテーブル名を指定する
 */
@Entity
@Table(name = "M_USER")
data class Muser(
    /**
     *  @Id：主キーに指定する。※複合キーの場合は@EmbeddedIdを使用
     *  @GeneratedValue：主キーの指定をJPAに委ねる
     *  @Column：name属性でマッピングするカラム名を指定する
     */
    @Id
    @Column(name="INTERNAL_ID")
    var internalId: String,

    @Column(name="USER_ID")
    var userId: String,

    @Column(name="DISPLAY_NAME")
    var displayName: String,

    @Column(name="PASSWORD")
    var password: String,

)
