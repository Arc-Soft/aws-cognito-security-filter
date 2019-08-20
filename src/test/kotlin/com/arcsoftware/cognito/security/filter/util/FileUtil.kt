package com.arcsoftware.cognito.security.filter.util


import org.apache.commons.io.IOUtils

import java.nio.charset.StandardCharsets.UTF_8

object FileUtil {

    fun jsonFile(fileName: String): String {
        return fileContent("json", fileName)
    }

    fun fileContent(dirPrefix: String, fileName: String): String {
        var name: String? = null
        try {
            name = "$dirPrefix/$fileName"
            return IOUtils.toString(FileUtil::class.java.classLoader.getResourceAsStream(name)!!, UTF_8)
        } catch (e: Exception) {
            throw RuntimeException("Error reading file " + name + ": " + e.message, e)
        }

    }

}