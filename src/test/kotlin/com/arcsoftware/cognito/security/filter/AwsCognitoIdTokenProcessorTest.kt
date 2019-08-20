package com.arcsoftware.cognito.security.filter


import com.arcsoftware.cognito.security.filter.config.JwtAutoConfiguration
import com.arcsoftware.cognito.security.filter.config.JwtIdTokenCredentialsHolder
import com.arcsoftware.cognito.security.filter.filter.AwsCognitoIdTokenProcessor
import com.arcsoftware.cognito.security.filter.util.FileUtil.jsonFile
import com.github.tomakehurst.wiremock.client.WireMock.aResponse
import com.github.tomakehurst.wiremock.client.WireMock.get
import com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo
import com.github.tomakehurst.wiremock.junit.WireMockRule
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jwt.proc.BadJWTException
import org.apache.http.HttpStatus.SC_OK
import org.assertj.core.api.Assertions.assertThat
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.context.web.WebAppConfiguration
import java.text.ParseException

@RunWith(SpringRunner::class)
@WebAppConfiguration
@ContextConfiguration(classes = [JwtAutoConfiguration::class], initializers = [ConfigFileApplicationContextInitializer::class])
class AwsCognitoIdTokenProcessorTest {

    @Rule @JvmField
    var wireMockRule = WireMockRule(65432)

    @Autowired
    lateinit var awsCognitoIdTokenProcessor: AwsCognitoIdTokenProcessor

    @Autowired
    lateinit var jwtIdTokenCredentialsHolder: JwtIdTokenCredentialsHolder

    private val request = MockHttpServletRequest()

    private val response = MockHttpServletResponse()

    private val userAuthentication = UsernamePasswordAuthenticationToken("marissa", "koala")

    @Before
    fun init() {
        setupJwkResource(JWKS)
    }

    @After
    fun clear() {
        SecurityContextHolder.clearContext()
    }

    @Test(expected = ParseException::class)
    @Throws(Exception::class)
    fun whenAuthorizationHeaderWithInvalidJWTValueProvidedParseExceptionOccurs() {
        request.addHeader("Authorization", "Invalid JWT")
        awsCognitoIdTokenProcessor!!.getAuthentication(request)
    }

    @Test(expected = ParseException::class)
    @Throws(Exception::class)
    fun whenAuthorizationHeaderWithEmptyJWTValueProvidedParseExceptionOccurs() {
        request.addHeader("Authorization", "")
        awsCognitoIdTokenProcessor!!.getAuthentication(request)
    }

    @Test
    @Throws(Exception::class)
    fun whenNoAuthorizationHeaderProvidedParseExceptionOccurs() {
        assertThat(awsCognitoIdTokenProcessor!!.getAuthentication(request)).isNull()
    }

    @Test(expected = ParseException::class)
    @Throws(Exception::class)
    fun whenUnsignedAuthorizationHeaderProvidedParseExceptionOccurs() {
        request.addHeader("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTMzNywidXNlcm5hbWUiOiJqb2huLmRvZSJ9")
        assertThat(awsCognitoIdTokenProcessor!!.getAuthentication(request)).isNull()
    }


    @Test(expected = BadJOSEException::class)
    @Throws(Exception::class)
    fun whenSignedJWTWithoutMatchingKeyInAuthorizationHeaderProvidedParseExceptionOccurs() {
        request.addHeader("Authorization", newJwtToken(UNKNOWN_KID, "role1").serialize())
        assertThat(awsCognitoIdTokenProcessor!!.getAuthentication(request)).isNull()
    }

    @Test
    @Throws(Exception::class)
    fun whenSignedJWTWithMatchingKeyInAuthorizationHeaderProvidedAuthenticationIsReturned() {
        request.addHeader("Authorization", newJwtToken(KNOWN_KID, "role1").serialize())
        val authentication = awsCognitoIdTokenProcessor!!.getAuthentication(request)
        assertThat(authentication!!.isAuthenticated).isTrue()
    }

    @Test(expected = BadJWTException::class)
    @Throws(Exception::class)
    fun whenExpiredJWTWithMatchingKeyInAuthorizationHeaderProvidedAuthenticationIsReturned() {
        request.addHeader("Authorization", newJwtToken(KNOWN_KID, "expired").serialize())
        awsCognitoIdTokenProcessor!!.getAuthentication(request)
    }


    protected fun setupJwkResource(assetResponse: String) {
        wireMockRule.stubFor(get(urlEqualTo("/.well-known/jwks.json"))
            .willReturn(
                aResponse()
                    .withBody(assetResponse)
                    .withStatus(SC_OK)
            ))
    }

    @Throws(Exception::class)
    private fun newJwtToken(kid: String, role: String): JWSObject {

        val rsaKey = RSAKey.parse(jsonFile("jwk/private_key.json"))
        val signer = RSASSASigner(rsaKey)

        val jwsObject = JWSObject(
            JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(),
            Payload(jsonFile("jwk/payload-$role.json")))

        jwsObject.sign(signer)

        return jwsObject

    }

    companion object {

        private val KNOWN_KID = "1486832567"
        private val UNKNOWN_KID = "000000000"

        protected val JWKS = jsonFile("jwk/keys.json")
    }

}