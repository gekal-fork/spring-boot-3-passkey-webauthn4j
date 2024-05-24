package com.example.springwebauthn4j

import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher

class UsernameAuthenticationFilter(
    pattern: String,
    httpMethod: String,
) : UsernamePasswordAuthenticationFilter() {
    init {
        setRequiresAuthenticationRequestMatcher(AntPathRequestMatcher(pattern, httpMethod))
    }
}
