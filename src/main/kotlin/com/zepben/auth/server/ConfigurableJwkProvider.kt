/*
 * Copyright 2024 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth.server

import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkProvider
import com.auth0.jwk.SigningKeyNotFoundException
import com.fasterxml.jackson.databind.ObjectMapper
import com.zepben.auth.client.SSLContextUtils
import com.zepben.auth.common.StatusCode
import java.net.URL
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

class ConfigurableJwkProvider(
    private val url: URL,
    verifyCertificates: Boolean,
    val httpClientCreator: () -> HttpClient = {
        if (!verifyCertificates) {
            HttpClient.newBuilder().sslContext(SSLContextUtils.allTrustingSSLContext()).build()
        } else {
            HttpClient.newBuilder().build()
        }
    }
) : JwkProvider {
    val allKeys by lazy { getAll() }

    private fun getAll(): List<Jwk> {
        val client = httpClientCreator()
        val request = HttpRequest.newBuilder()
            .uri(url.toURI())
            .header(CONTENT_TYPE, "application/json")
            .GET()
            .build()

        val response = client.send(request, HttpResponse.BodyHandlers.ofString())

        if (response.statusCode() != StatusCode.OK.code) {
            throw SigningKeyNotFoundException("Cannot obtain jwks from url $url", null)
        }

        val reader = ObjectMapper().readerFor(MutableMap::class.java)
        val thing = reader.readValue<Map<String, Any>>(response.body())

        val keys = thing["keys"] as List<Map<String, Any>>

        return keys.map { Jwk.fromValues(it) }
    }

    override fun get(keyId: String?): Jwk {
        return allKeys.firstOrNull { it.id == keyId } ?: throw SigningKeyNotFoundException("No key found in $url with kid $keyId", null)
    }
}
