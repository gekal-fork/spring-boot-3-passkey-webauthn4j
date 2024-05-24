package com.example.springwebauthn4j.repository

import org.springframework.data.jpa.repository.JpaRepository

// テーブルへアクセスするための基本的な処理はJPAが用意してくれているのでSQLを書かなくてよい
// JPAのJpaRepositoryを継承したinterfaceを作成することで利用できる
//  - findAll()など基本的なメソッドは持っている

/**
 * Entityと主キーの型をジェネリクスに指定したJpaRepositoryを継承する
 * Entity：User、主キーの型：String
 *
 * Spring Data JPAで提供されているAPIではできない処理を記述する
 *
 * ※カスタムメソッドを実装したクラスのインターフェースを指定することで、カスタムメソッドを追加可能
 */
interface MuserRepository : JpaRepository<Muser, String> {
    fun findByInternalId(internalId: String): Muser?
    fun findByUserId(userId: String): Muser?
}
