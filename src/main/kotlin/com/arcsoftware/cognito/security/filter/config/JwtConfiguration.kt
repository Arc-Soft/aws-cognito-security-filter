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