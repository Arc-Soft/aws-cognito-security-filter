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
package com.arcsoftware.cognito.security.filter.config


import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.stereotype.Component

@Component
@ConfigurationProperties(prefix = "com.arcsoftware.security.jwt.aws")
class JwtConfiguration {

    var userPoolId: String? = null
    private var identityPoolId: String? = null

    var jwkUrl: String? = null
        get() = if (field == null || field!!.isEmpty()) {
            String.format(COGNITO_IDENTITY_POOL_URL + JSON_WEB_TOKEN_SET_URL_SUFFIX, region, userPoolId)
        } else field
    var region = "us-west-2"
    var userNameField = "cognito:username"
    var groupsField = "cognito:groups"
    var connectionTimeout = 2000
    var readTimeout = 2000
    var httpHeader = "Authorization"

    val cognitoIdentityPoolUrl: String
        get() = String.format(COGNITO_IDENTITY_POOL_URL, region, userPoolId)

    fun getIdentityPoolId(): String? {
        return identityPoolId
    }

    fun setIdentityPoolId(identityPoolId: String): JwtConfiguration {
        this.identityPoolId = identityPoolId
        return this
    }

    companion object {

        private val COGNITO_IDENTITY_POOL_URL = "https://cognito-idp.%s.amazonaws.com/%s"
        private val JSON_WEB_TOKEN_SET_URL_SUFFIX = "/.well-known/jwks.json"
    }

}