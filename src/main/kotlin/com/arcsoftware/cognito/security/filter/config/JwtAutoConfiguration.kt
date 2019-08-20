package com.arcsoftware.cognito.security.filter.config


import com.arcsoftware.cognito.security.filter.filter.AwsCognitoIdTokenProcessor
import com.arcsoftware.cognito.security.filter.filter.AwsCognitoJwtAuthenticationFilter
import com.nimbusds.jose.JWSAlgorithm.RS256
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.DefaultResourceRetriever
import com.nimbusds.jose.util.ResourceRetriever
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Scope
import org.springframework.context.annotation.ScopedProxyMode
import java.net.MalformedURLException
import java.net.URL

/**
 *
 * Our auto configuration class that exposes
 *
 * - CredentialHolder
 * - JWTProcessor
 * - AuthenticationProvider
 * - JWTAuthenticationFilter
 * - AwsCognitoJtwConfiguration
 *
 */
@Configuration
@ConditionalOnClass(AwsCognitoJwtAuthenticationFilter::class, AwsCognitoIdTokenProcessor::class)
@EnableConfigurationProperties(JwtConfiguration::class)
class JwtAutoConfiguration {

    @Autowired
    private val jwtConfiguration: JwtConfiguration? = null

    @Bean
    @Scope(value = "request", proxyMode = ScopedProxyMode.TARGET_CLASS)
    fun awsCognitoCredentialsHolder(): JwtIdTokenCredentialsHolder {
        return JwtIdTokenCredentialsHolder()
    }

    @Bean
    fun awsCognitoIdTokenProcessor(): AwsCognitoIdTokenProcessor {
        return AwsCognitoIdTokenProcessor()
    }

    @Bean
    fun jwtAuthenticationProvider(): JwtAuthenticationProvider {
        return JwtAuthenticationProvider()
    }


    @Bean
    fun awsCognitoJwtAuthenticationFilter(): AwsCognitoJwtAuthenticationFilter {
        return AwsCognitoJwtAuthenticationFilter(awsCognitoIdTokenProcessor())
    }

    @Bean
    @Throws(MalformedURLException::class)
    fun configurableJWTProcessor(): ConfigurableJWTProcessor<*> {
        val resourceRetriever: ResourceRetriever = DefaultResourceRetriever(jwtConfiguration!!.connectionTimeout, jwtConfiguration.readTimeout)
        val jwkSetURL = URL(jwtConfiguration.jwkUrl)
        val keySource = RemoteJWKSet<SecurityContext>(jwkSetURL, resourceRetriever)
        val jwtProcessor = DefaultJWTProcessor<SecurityContext>()
        val keySelector = JWSVerificationKeySelector(RS256, keySource)
        jwtProcessor.jwsKeySelector = keySelector
        return jwtProcessor
    }

}