package com.arcsoftware.cognito.security.filter


import com.nimbusds.jwt.JWTClaimsSet
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority

/**
 *
 * Value object holding the principal, the JWT clailmset and the granted authorities.
 * This is the authentication object that will be made available in the security context.
 *
 */
class JwtAuthentication(private val principal: Any, val jwtClaimsSet: JWTClaimsSet, authorities: Collection<GrantedAuthority>) : AbstractAuthenticationToken(authorities) {

    init {
        super.setAuthenticated(true)
    }

    override fun getCredentials(): Any? {
        return null
    }

    override fun getPrincipal(): Any {
        return principal
    }
}