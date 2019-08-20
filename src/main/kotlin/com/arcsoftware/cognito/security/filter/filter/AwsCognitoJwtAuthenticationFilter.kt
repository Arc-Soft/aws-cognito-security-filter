package com.arcsoftware.cognito.security.filter.filter


import org.slf4j.LoggerFactory
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.GenericFilterBean
import java.io.IOException
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest

class AwsCognitoJwtAuthenticationFilter(private val awsCognitoIdTokenProcessor: AwsCognitoIdTokenProcessor) : GenericFilterBean() {

    @Throws(IOException::class, ServletException::class)
    override fun doFilter(request: ServletRequest, response: ServletResponse, filterChain: FilterChain) {

        var authentication: Authentication? = null
        try {
            authentication = awsCognitoIdTokenProcessor.getAuthentication(request as HttpServletRequest)

            if (authentication != null) {
                SecurityContextHolder.getContext().authentication = authentication
            }

        } catch (e: Exception) {
            logger.error("Error occured while processing Cognito ID Token", e)
            SecurityContextHolder.clearContext()
            //return;
            //throw new ServletException("Error occured while processing Cognito ID Token",e);
        }

        filterChain.doFilter(request, response)

    }

    companion object {

        private val logger = LoggerFactory.getLogger(AwsCognitoJwtAuthenticationFilter::class.java)
    }
}