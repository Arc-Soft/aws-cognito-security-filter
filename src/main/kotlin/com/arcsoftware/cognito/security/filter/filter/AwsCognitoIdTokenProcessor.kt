/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2016-present IxorTalk CVBA
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.arcsoftware.cognito.security.filter.filter


import com.arcsoftware.cognito.security.filter.JwtAuthentication
import com.arcsoftware.cognito.security.filter.config.JwtConfiguration
import com.arcsoftware.cognito.security.filter.config.JwtIdTokenCredentialsHolder
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import org.apache.commons.logging.LogFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import javax.servlet.http.HttpServletRequest

class AwsCognitoIdTokenProcessor {

    @Autowired
    private val jwtConfiguration: JwtConfiguration? = null

    @Autowired
    private val configurableJWTProcessor: ConfigurableJWTProcessor<*>? = null

    @Autowired
    private val jwtIdTokenCredentialsHolder: JwtIdTokenCredentialsHolder? = null

    @Throws(Exception::class)
    fun getAuthentication(request: HttpServletRequest): Authentication? {

        val idToken = request.getHeader(jwtConfiguration!!.httpHeader)
        if (idToken != null) {

            val claimsSet: JWTClaimsSet? = configurableJWTProcessor!!.process(stripBearerToken(idToken), null)

            if (!isIssuedCorrectly(claimsSet!!)) {
                throw Exception(String.format("Issuer %s in JWT token doesn't match cognito idp %s", claimsSet.issuer, jwtConfiguration.cognitoIdentityPoolUrl))
            }

            if (!isIdToken(claimsSet)) {
                throw Exception("JWT Token doesn't seem to be an ID Token")
            }

            val username = claimsSet.claims[jwtConfiguration.userNameField]?.toString()

            if (username != null) {
                val groups = claimsSet.claims[jwtConfiguration.groupsField]?.let { it as List<String> }
                val grantedAuthorities = groups?.map {
                    SimpleGrantedAuthority(ROLE_PREFIX + it.toUpperCase())
                } ?: emptyList()
                val user = User(username, EMPTY_PWD, grantedAuthorities)

                jwtIdTokenCredentialsHolder!!.idToken = stripBearerToken(idToken)
                return JwtAuthentication(user, claimsSet, grantedAuthorities)
            }

        }

        logger.trace("No idToken found in HTTP Header")
        return null
    }

    private fun stripBearerToken(token: String): String {
        return if (token.startsWith(BEARER_PREFIX)) token.substring(BEARER_PREFIX.length) else token
    }

    private fun isIssuedCorrectly(claimsSet: JWTClaimsSet): Boolean {
        return claimsSet.issuer == jwtConfiguration!!.cognitoIdentityPoolUrl
    }

    private fun isIdToken(claimsSet: JWTClaimsSet): Boolean {
        return claimsSet.getClaim("token_use") == "id"
    }

    companion object {

        private val logger = LogFactory.getLog(AwsCognitoIdTokenProcessor::class.java)

        private val ROLE_PREFIX = "ROLE_"
        private val EMPTY_PWD = ""
        private val BEARER_PREFIX = "Bearer "

    }
}