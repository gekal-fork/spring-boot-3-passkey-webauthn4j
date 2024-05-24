package com.example.springwebauthn4j.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher

@Configuration
@EnableWebSecurity
class H2ConsoleSecurityConfig {

    @Bean
    @Order(1)
    fun h2ConsoleSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .securityMatcher(antMatcher("/h2-console/**"))
            .authorizeHttpRequests { authorizeRequests ->
                authorizeRequests
                    .anyRequest().permitAll()
            }
            .headers { headers ->
                headers.frameOptions { it.disable() }
            }
            .csrf { csrf ->
                csrf.disable()
            }

        return http.build()
    }

}
