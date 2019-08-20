package com.arcsoftware.cognito.security.filter.config


import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException

class JwtAuthenticationProvider : AuthenticationProvider {

    @Throws(AuthenticationException::class)
    override fun authenticate(authentication: Authentication): Authentication {
        return authentication
    }

    override fun supports(authentication: Class<*>): Boolean {
        return true
    }
}