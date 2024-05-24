package com.example.springwebauthn4j.config

import com.example.springwebauthn4j.CustomAuthenticationFailureHandler
import com.example.springwebauthn4j.Fido2AuthenticationFilter
import com.example.springwebauthn4j.Fido2AuthenticationProvider
import com.example.springwebauthn4j.PasswordAuthenticationFilter
import com.example.springwebauthn4j.PasswordAuthenticationProvider
import com.example.springwebauthn4j.UsernameAuthenticationFilter
import com.example.springwebauthn4j.UsernameAuthenticationProvider
import com.example.springwebauthn4j.UsernameAuthenticationSuccessHandler
import com.example.springwebauthn4j.service.SampleUserDetailsService
import com.example.springwebauthn4j.util.SecurityContextUtil
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.context.DelegatingSecurityContextRepository
import org.springframework.security.web.context.HttpSessionSecurityContextRepository


@Configuration
@EnableWebSecurity
class WebSecurityConfig(
    @Autowired private val usernameAuthenticationProvider: UsernameAuthenticationProvider,
    @Autowired private val passwordAuthenticationProvider: PasswordAuthenticationProvider,
    @Autowired private val fido2AuthenticationProvider: Fido2AuthenticationProvider,
    @Autowired private val userDetailsService: SampleUserDetailsService
) {

    @Bean
    fun securityFilterChain(
        http: HttpSecurity,
        authenticationManager: AuthenticationManager,
    ): SecurityFilterChain {

        http
            .authorizeHttpRequests { authorizeRequests ->
                authorizeRequests
                    .requestMatchers("/css/**", "/js/**", "/images/**").permitAll()
                    .requestMatchers("/login", "/login-fido2", "/authenticate/option").permitAll()
                    .requestMatchers("/password").hasAnyAuthority(SecurityContextUtil.Auth.AUTHENTICATED_USERNAME.value)
                    .requestMatchers("/**").hasRole(SecurityContextUtil.Role.USER.name)
            }
            .formLogin { formLogin ->
                formLogin
                    .loginPage("/login").permitAll()
            }
            .addFilterAt(
                createUsernameAuthenticationFilter(authenticationManager),
                UsernamePasswordAuthenticationFilter::class.java
            )
            .addFilterAt(
                createPasswordAuthenticationFilter(authenticationManager),
                UsernamePasswordAuthenticationFilter::class.java
            )
            .addFilterAt(
                createFido2AuthenticationFilter(authenticationManager),
                UsernamePasswordAuthenticationFilter::class.java
            )
            .csrf { csrf ->
                csrf.ignoringRequestMatchers(
                    "/authenticate/option",
                    "/register/option",
                    "/register/verify"
                )
            }
            .headers { headers ->
                headers.frameOptions { it.disable() }
            }
            .authenticationManager(authenticationManager)

        return http.build()
    }

    @Bean
    fun authenticationManager(
        http: HttpSecurity
    ): AuthenticationManager {
        return createAuthenticationManagerBuilder(http).build()
    }

    private fun createAuthenticationManagerBuilder(http: HttpSecurity): AuthenticationManagerBuilder {
        val auth = http.getSharedObject(AuthenticationManagerBuilder::class.java)
        configure(auth)
        return auth
    }

    private fun configure(auth: AuthenticationManagerBuilder) {
        // setUserDetailsService
        usernameAuthenticationProvider.setUserDetailsService(userDetailsService)
        passwordAuthenticationProvider.setUserDetailsService(userDetailsService)

        // authenticationProvider
        auth.authenticationProvider(usernameAuthenticationProvider)
        auth.authenticationProvider(passwordAuthenticationProvider)
        auth.authenticationProvider(fido2AuthenticationProvider)
    }

    @Bean
    fun authenticationFilter(
        authenticationManager: AuthenticationManager
    ): UsernamePasswordAuthenticationFilter {
        return createPasswordAuthenticationFilter(authenticationManager)
    }

    private fun createUsernameAuthenticationFilter(authenticationManager: AuthenticationManager): UsernamePasswordAuthenticationFilter {
        return UsernameAuthenticationFilter("/login", "POST").apply {
            setSecurityContextRepository(
                DelegatingSecurityContextRepository(
                    HttpSessionSecurityContextRepository()
                )
            )
            setAuthenticationManager(authenticationManager)
            setAuthenticationSuccessHandler(UsernameAuthenticationSuccessHandler("/password", "/mypage"))
            setAuthenticationFailureHandler(CustomAuthenticationFailureHandler("/login?error"))
        }
    }

    private fun createPasswordAuthenticationFilter(authenticationManager: AuthenticationManager): PasswordAuthenticationFilter {
        return PasswordAuthenticationFilter("/password", "POST").apply {
            setSecurityContextRepository(
                DelegatingSecurityContextRepository(
                    HttpSessionSecurityContextRepository()
                )
            )
            setAuthenticationManager(authenticationManager)
            setAuthenticationSuccessHandler(SimpleUrlAuthenticationSuccessHandler("/mypage"))
            setAuthenticationFailureHandler(CustomAuthenticationFailureHandler("/login?error"))
        }
    }

    private fun createFido2AuthenticationFilter(authenticationManager: AuthenticationManager): Fido2AuthenticationFilter {
        return Fido2AuthenticationFilter("/login-fido2", "POST").apply {
            setSecurityContextRepository(
                DelegatingSecurityContextRepository(
                    HttpSessionSecurityContextRepository()
                )
            )

            setAuthenticationManager(authenticationManager)
            setAuthenticationSuccessHandler(SimpleUrlAuthenticationSuccessHandler("/mypage"))
            setAuthenticationFailureHandler(CustomAuthenticationFailureHandler("/login?error"))
        }
    }

}
