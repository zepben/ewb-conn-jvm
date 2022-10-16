// Copyright 2022 Zeppelin Bend Pty Ltd
// This file is part of zepben-auth.
//
// zepben-auth is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// zepben-auth is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with zepben-auth.  If not, see <https://www.gnu.org/licenses/>.


package com.zepben.auth.client

import com.auth0.jwt.JWT
import com.zepben.auth.common.AuthException
import com.zepben.auth.common.AuthMethod
import com.zepben.auth.common.StatusCode
import io.vertx.core.json.DecodeException
import java.net.URL
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Instant
import io.vertx.core.json.Json
import io.vertx.core.json.JsonObject
import java.net.URI
import javax.net.ssl.SSLContext
import kotlin.Exception

/**
 * @property audience Audience to use when requesting tokens.
 * @property issuerDomain The domain of the token issuer.
 * @property authMethod The authentication method used by the server.
 * @property issuerProtocol Protocol of the token issuer. You should not change this unless you are absolutely sure of
 *                          what you are doing. Setting it to anything other than https is a major security risk as
 *                          tokens will be sent in the clear.
 * @property tokenPath Path for requesting token from `issuer_domain`.
 * @property tokenRequestData Data to pass in token requests.
 * @property refreshRequestData Data to pass in refresh token requests.
 * @property client HTTP client used to retrieve tokens. Defaults to HttpClient.newHttpClient().
 */
data class ZepbenTokenFetcher(
    val audience: String,
    val issuerDomain: String,
    val authMethod: AuthMethod,
    val issuerProtocol: String = "https",
    val tokenPath: String = "/oauth/token",
    val tokenRequestData: JsonObject = JsonObject(),
    val refreshRequestData: JsonObject = JsonObject(),
    private val client: HttpClient,
    private var refreshToken: String? = null
) {
    private var accessToken: String? = null
    private var tokenExpiry: Instant = Instant.MIN
    private var tokenType: String? = null

    /**
     * @property audience Audience to use when requesting tokens.
     * @property issuerDomain The domain of the token issuer.
     * @property authMethod The authentication method used by the server.
     * @property verifyCertificate Whether to verify the SSL certificate when making requests.
     * @property issuerProtocol Protocol of the token issuer. You should not change this unless you are absolutely sure of
     *                          what you are doing. Setting it to anything other than https is a major security risk as
     *                          tokens will be sent in the clear.
     * @property tokenPath Path for requesting token from `issuer_domain`.
     * @property tokenRequestData Data to pass in token requests.
     * @property refreshRequestData Data to pass in refresh token requests.
     */
    constructor(
        audience: String,
        issuerDomain: String,
        authMethod: AuthMethod,
        issuerProtocol: String = "https",
        tokenPath: String = "/oauth/token",
        tokenRequestData: JsonObject = JsonObject(),
        refreshRequestData: JsonObject = JsonObject(),
        refreshToken: String? = null,
        verifyCertificate: Boolean
    ) : this(
        audience, issuerDomain, authMethod, issuerProtocol, tokenPath, tokenRequestData, refreshRequestData,
        HttpClient.newBuilder()
            .sslContext(
                if (verifyCertificate) SSLContext.getDefault() else SSLContextUtils.allTrustingSSLContext()
            )
            .build(),
        refreshToken
    )

    /**
     * @property audience Audience to use when requesting tokens.
     * @property issuerDomain The domain of the token issuer.
     * @property authMethod The authentication method used by the server.
     * @property caFilename Filename of X.509 CA certificate used to verify HTTPS responses from token service.
     * @property issuerProtocol Protocol of the token issuer. You should not change this unless you are absolutely sure of
     *                          what you are doing. Setting it to anything other than https is a major security risk as
     *                          tokens will be sent in the clear.
     * @property tokenPath Path for requesting token from `issuer_domain`.
     * @property tokenRequestData Data to pass in token requests.
     * @property refreshRequestData Data to pass in refresh token requests.
     */
    constructor(
        audience: String,
        issuerDomain: String,
        authMethod: AuthMethod,
        issuerProtocol: String = "https",
        tokenPath: String = "/oauth/token",
        tokenRequestData: JsonObject = JsonObject(),
        refreshRequestData: JsonObject = JsonObject(),
        refreshToken: String? = null,
        caFilename: String? = null
    ) : this(
        audience, issuerDomain, authMethod, issuerProtocol, tokenPath, tokenRequestData, refreshRequestData,
        caFilename?.let {
            HttpClient.newBuilder()
                .sslContext(SSLContextUtils.singleCACertSSLContext(it))
                .build()
        } ?: HttpClient.newHttpClient(),
        refreshToken
    )

    init {
        tokenRequestData.put("audience", audience)
        refreshRequestData.put("audience", audience)
    }

    /**
     * Returns a JWT access token and its type in the form of '<type> <3 part JWT>', retrieved from the configured
     * OAuth2 token provider. Throws an Exception if an access token request fails.
     */
    fun fetchToken(): String {
        if (Instant.now() > tokenExpiry) {
            // Stored token has expired, try to refresh
            accessToken = null
            if (!refreshToken.isNullOrEmpty()) {
                fetchTokenAuth0(useRefresh = true)
            }

            if (accessToken == null) {
                // If using the refresh token did not work for any reason, self._access_token will still be None.
                // and thus we must try to get a fresh access token using credentials instead.
                fetchTokenAuth0()
            }

            if (tokenType.isNullOrEmpty() or accessToken.isNullOrEmpty()) {
                throw Exception(
                    "Token couldn't be retrieved from ${URL(issuerProtocol, issuerDomain, tokenPath)} using " +
                    "configuration $authMethod, audience: $audience, token issuer: $issuerDomain"
                )
            }
        }

        return "$tokenType $accessToken"
    }

    private fun fetchTokenAuth0(useRefresh: Boolean = false) {
        val body = if (useRefresh) refreshRequestData.toString() else tokenRequestData.toString()
        val request = HttpRequest.newBuilder()
            .uri(URL(issuerProtocol, issuerDomain, tokenPath).toURI())
            .header("content-type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()
        val response = client.send(request, HttpResponse.BodyHandlers.ofString())

        if (response.statusCode() != StatusCode.OK.code) {
            throw AuthException(
                response.statusCode(),
                "Token fetch failed, Error was: ${response.statusCode()} - ${response.body()}"
            )
        }

        val data: JsonObject
        try {
            data = Json.decodeValue(response.body()) as JsonObject
        } catch (e: DecodeException) {
            throw AuthException(
                response.statusCode(),
                "Response did not contain valid JSON - response was: ${response.body()}"
            )
        } catch (e: ClassCastException) {
            throw AuthException(
                response.statusCode(),
                "Response was not a JSON object - response was: ${response.body()}"
            )
        }

        if (data.containsKey("error") or !data.containsKey("access_token")) {
            throw AuthException(
                response.statusCode(),
                (data.getString("error") ?: "Access Token absent in token response") + " - " +
                (data.getString("error_description") ?: "Response was: $data")
            )
        }

        tokenType = data.getString("token_type")
        accessToken = data.getString("access_token")
        tokenExpiry = JWT.decode(accessToken).getClaim("exp")?.asDate()?.toInstant() ?: Instant.MIN

        if (useRefresh) {
            refreshToken = data.getString("refresh_token")
        }
    }
}


/**
 * Helper method to fetch auth related configuration from `confAddress` and create a `ZepbenTokenFetcher`
 *
 * @param confAddress Location to retrieve authentication configuration from. Must be a HTTP address that returns a JSON response.
 * @param authTypeField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 * @param audienceField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 * @param issuerDomainField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 * @param confClient HTTP client used to retrieve authentication configuration. Defaults to HttpClient.newHttpClient().
 * @param authClient HTTP client used to retrieve tokens. Defaults to HttpClient.newHttpClient().
 *
 * @returns: A `ZepbenTokenFetcher` if the server reported authentication was configured, otherwise None.
 */
fun createTokenFetcher(
    confAddress: String,
    authTypeField: String = "authType",
    audienceField: String = "audience",
    issuerDomainField: String = "issuer",
    confClient: HttpClient,
    authClient: HttpClient
): ZepbenTokenFetcher? {
    val request = HttpRequest.newBuilder().uri(URI(confAddress)).GET().build()
    val response = confClient.send(request, HttpResponse.BodyHandlers.ofString())
    if (response.statusCode() == StatusCode.OK.code) {
        try {
            val authConfigJson = Json.decodeValue(response.body()) as JsonObject
            val authMethod = AuthMethod.valueOf(authConfigJson.getString(authTypeField))
            if (authMethod != AuthMethod.NONE) {
                return ZepbenTokenFetcher(
                    authConfigJson.getString(audienceField),
                    authConfigJson.getString(issuerDomainField),
                    authMethod,
                    client = authClient
                )
            }
        } catch (e: DecodeException) {
            throw AuthException(
                response.statusCode(),
                "Expected JSON response from $confAddress, but got: ${response.body()}."
            )
        } catch (e: ClassCastException) {
            throw AuthException(
                response.statusCode(),
                "Expected JSON object from $confAddress, but got: ${response.body()}."
            )
        }
    } else {
        throw AuthException(
            response.statusCode(),
            "$confAddress responded with error: ${response.statusCode()} - ${response.body()}"
        )
    }
    return null
}

/**
 * Helper method to fetch auth related configuration from `confAddress` and create a `ZepbenTokenFetcher`
 *
 * @param confAddress Location to retrieve authentication configuration from. Must be a HTTP address that returns a JSON response.
 * @param authTypeField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 * @param audienceField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 * @param issuerDomainField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 * @param verifyCertificates: Whether to verify the certificate when making HTTPS requests. Note you should only use a trusted server
 *                            and never set this to False in a production environment.
 *
 * @returns: A `ZepbenTokenFetcher` if the server reported authentication was configured, otherwise None.
 */
fun createTokenFetcher(
    confAddress: String,
    authTypeField: String = "authType",
    audienceField: String = "audience",
    issuerDomainField: String = "issuer",
    verifyCertificates: Boolean
) = createTokenFetcher(
    confAddress,
    authTypeField,
    audienceField,
    issuerDomainField,
    confClient = HttpClient.newBuilder().sslContext(
        if (verifyCertificates) SSLContext.getDefault() else SSLContextUtils.allTrustingSSLContext()
    ).build(),
    authClient = HttpClient.newBuilder().sslContext(
        if (verifyCertificates) SSLContext.getDefault() else SSLContextUtils.allTrustingSSLContext()
    ).build()
)

/**
 * Helper method to fetch auth related configuration from `confAddress` and create a `ZepbenTokenFetcher`
 *
 * @param confAddress Location to retrieve authentication configuration from. Must be a HTTP address that returns a JSON response.
 * @param confCAFilename Filename of X.509 CA certificate used to verify HTTPS responses from configuration service. Leave as null to use system CAs.
 * @param authCAFilename Filename of X.509 CA certificate used to verify HTTPS responses from token service. Leave as null to use system CAs.
 * @param authTypeField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 * @param audienceField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 * @param issuerDomainField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 *
 * @returns: A `ZepbenTokenFetcher` if the server reported authentication was configured, otherwise None.
 */
fun createTokenFetcher(
    confAddress: String,
    authTypeField: String = "authType",
    audienceField: String = "audience",
    issuerDomainField: String = "issuer",
    confCAFilename: String? = null,
    authCAFilename: String? = null,
) = createTokenFetcher(
    confAddress,
    authTypeField,
    audienceField,
    issuerDomainField,
    confClient = confCAFilename?.let {
        HttpClient.newBuilder().sslContext(SSLContextUtils.singleCACertSSLContext(it)).build()
    } ?: HttpClient.newHttpClient(),
    authClient = authCAFilename?.let {
        HttpClient.newBuilder().sslContext(SSLContextUtils.singleCACertSSLContext(it)).build()
    } ?: HttpClient.newHttpClient(),
)
