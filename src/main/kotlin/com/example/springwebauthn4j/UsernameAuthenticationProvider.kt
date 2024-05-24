package com.example.springwebauthn4j

import com.example.springwebauthn4j.util.SecurityContextUtil
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component

@Component
class UsernameAuthenticationProvider: DaoAuthenticationProvider() {
    override fun doAfterPropertiesSet() {
        // NOP これをしとかないと A UserDetailsService must be set が発生して @autowired できない
        // UserDetailsServiceのセットはSampleWebSecurityConfig.configure()で行っている
    }

    override fun supports(authentication: Class<*>?): Boolean {
        // このProviderの処理対象かどうかをチェックする
        // 既にユーザーIDが求まっている場合は処理不要のため、falseで返す
        return if (SecurityContextUtil.isUsernameAuthenticated()){
            false
        } else {
            super.supports(authentication)
        }
    }

    override fun additionalAuthenticationChecks(
        userDetails: UserDetails?,
        authentication: UsernamePasswordAuthenticationToken?
    ) {
        // NOP パスワードのチェックを行わない
    }

}
