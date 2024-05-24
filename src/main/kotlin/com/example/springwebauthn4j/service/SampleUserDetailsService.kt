package com.example.springwebauthn4j.service

import com.example.springwebauthn4j.repository.MuserRepository
import com.example.springwebauthn4j.util.SecurityContextUtil
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service


@Service
class SampleUserDetailsService(
    private val mUserRepository: MuserRepository,
) : UserDetailsService {
    override fun loadUserByUsername(userId: String?): UserDetails {
        if (userId.isNullOrEmpty()) {
            throw UsernameNotFoundException("userId is null or empty")
        }

        val mUser = mUserRepository.findByUserId(userId) ?: throw UsernameNotFoundException("Not found userId")

        val authorities = if (SecurityContextUtil.isUsernameAuthenticated()) {
            listOf(
                SimpleGrantedAuthority(SecurityContextUtil.Auth.AUTHENTICATED_PASSWORD.value),
                SimpleGrantedAuthority(SecurityContextUtil.Role.USER.value)
            )
        } else {
            listOf(SimpleGrantedAuthority(SecurityContextUtil.Auth.AUTHENTICATED_USERNAME.value))
        }

        return User(mUser.userId, mUser.password, authorities)
    }
}
