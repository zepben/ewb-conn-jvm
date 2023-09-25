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
import com.zepben.auth.server.CONTENT_TYPE
import io.vertx.core.json.DecodeException
import io.vertx.core.json.Json
import io.vertx.core.json.JsonObject
import java.net.URI
import java.net.URL
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Instant

/**
 * Fetches access tokens from an authentication provider using the OAuth 2.0 protocol.
 *
 * @property audience Audience to use when requesting tokens.
 * @property issuerDomain The domain of the token issuer.
 * @property authMethod The authentication method used by the server.
 * @property issuerProtocol Protocol of the token issuer. You should not change this unless you are absolutely sure of
 *                          what you are doing. Setting it to anything other than https is a major security risk as
 *                          tokens will be sent in the clear.
 * @property requestContentType  content type for the OAUTH2 request.
 * @property tokenPath Path for requesting token from `issuer_domain`.
 * @property tokenRequestData Data to pass in token requests.
 * @property refreshRequestData Data to pass in refresh token requests.
 * @property client HTTP client used to retrieve tokens. Defaults to HttpClient.newHttpClient().
 * @property refreshToken Refresh Token; will be used if defined (fetched previously).
 * @property createBody a callback to turn the <*>RequestData into a string. AUTH0 requires JSON representation, where AZURE is query params.
 */
data class ZepbenTokenFetcher(
    val audience: String,
    val issuerDomain: String,
    val authMethod: AuthMethod,
    val issuerProtocol: String = "https",
    val tokenPath: String = "/oauth/token",
    val tokenRequestData: JsonObject = JsonObject(),
    val refreshRequestData: JsonObject = JsonObject(),
    private val client: HttpClient = HttpClient.newHttpClient(),
    private var refreshToken: String? = null,
    val requestContentType: String = "application/json",
    val createBody: (JsonObject) -> String = { it.toString() }
) {
    private var accessToken: String? = null
    private var tokenExpiry: Instant = Instant.MIN
    private var tokenType: String? = null

    /**
     * Create a ZepbenTokenFetcher with the option of turning off certificate verification for the token provider.
     *
     * @property audience Audience to use when requesting tokens.
     * @property issuerDomain The domain of the token issuer.
     * @property authMethod The authentication method used by the server.
     * @property verifyCertificate Whether to verify the SSL certificate of the token provider when making requests.
     * @property issuerProtocol Protocol of the token issuer. You should not change this unless you are absolutely sure of
     *                          what you are doing. Setting it to anything other than https is a major security risk as
     *                          tokens will be sent in the clear.
     * @property requestContentType  content type for the OAUTH2 request.
     * @property tokenPath Path for requesting token from `issuer_domain`.
     * @property tokenRequestData Data to pass in token requests.
     * @property refreshRequestData Data to pass in refresh token requests.
     * @property createBody a callback to turn the <*>RequestData into a string. AUTH0 requires JSON representation, where AZURE is query params.
     */
    constructor(
        audience: String,
        issuerDomain: String,
        authMethod: AuthMethod,
        verifyCertificate: Boolean,
        issuerProtocol: String = "https",
        requestContentType: String = "application/json",
        tokenPath: String = "/oauth/token",
        tokenRequestData: JsonObject = JsonObject(),
        refreshRequestData: JsonObject = JsonObject(),
        createBody: (JsonObject) -> String = { it.toString() }
    ) : this(
        audience = audience,
        issuerDomain = issuerDomain,
        authMethod = authMethod,
        issuerProtocol = issuerProtocol,
        tokenPath = tokenPath,
        tokenRequestData = tokenRequestData,
        refreshRequestData = refreshRequestData,
        client = if (verifyCertificate) HttpClient.newHttpClient() else HttpClient.newBuilder().sslContext(SSLContextUtils.allTrustingSSLContext()).build(),
        requestContentType = requestContentType,
        createBody = createBody
    )

    /**
     * Create a ZepbenTokenFetcher that uses a given CA to verify the token provider.
     *
     * @property audience Audience to use when requesting tokens.
     * @property issuerDomain The domain of the token issuer.
     * @property authMethod The authentication method used by the server.
     * @property caFilename Filename of X.509 CA certificate used to verify HTTPS responses from token service.
     * @property issuerProtocol Protocol of the token issuer. You should not change this unless you are absolutely sure of
     *                          what you are doing. Setting it to anything other than https is a major security risk as
     *                          tokens will be sent in the clear.
     * @property requestContentType  content type for the OAUTH2 request.
     * @property tokenPath Path for requesting token from `issuer_domain`.
     * @property tokenRequestData Data to pass in token requests.
     * @property refreshRequestData Data to pass in refresh token requests.
     * @property createBody a callback to turn the <*>RequestData into a string. AUTH0 requires JSON representation, where AZURE is query params.
     */
    constructor(
        audience: String,
        issuerDomain: String,
        authMethod: AuthMethod,
        caFilename: String?,
        issuerProtocol: String = "https",
        requestContentType: String = "application/json",
        tokenPath: String = "/oauth/token",
        tokenRequestData: JsonObject = JsonObject(),
        refreshRequestData: JsonObject = JsonObject(),
        createBody: (JsonObject) -> String = { it.toString() }
    ) : this(
        audience = audience,
        issuerDomain = issuerDomain,
        authMethod = authMethod,
        issuerProtocol = issuerProtocol,
        tokenPath = tokenPath,
        tokenRequestData = tokenRequestData,
        refreshRequestData = refreshRequestData,
        client = caFilename?.let {
            HttpClient.newBuilder().sslContext(SSLContextUtils.singleCACertSSLContext(caFilename)).build()
        } ?: HttpClient.newHttpClient(),
        requestContentType = requestContentType,
        createBody = createBody
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
                fetchOAuthToken(useRefresh = true)
            }

            if (accessToken == null) {
                // If using the refresh token did not work for any reason, self.accessToken will still be None.
                // and thus we must try to get a fresh access token using credentials instead.
                fetchOAuthToken()
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

    private fun fetchOAuthToken(useRefresh: Boolean = false) {
        val body = if (useRefresh) {
            refreshRequestData.put("refresh_token", refreshToken)
            createBody(refreshRequestData)
        } else createBody(tokenRequestData)

        val issuer = if (issuerDomain.startsWith("https://"))
            issuerDomain
        else "https://$issuerDomain"

        val request = HttpRequest.newBuilder()
            .uri(URL("$issuer/$tokenPath").toURI())
            .header(CONTENT_TYPE, requestContentType)
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
 * Helper method to fetch auth related configuration from `confAddress` and create a `ZepbenTokenFetcher`.
 * You must specify the `HttpClient`s used for fetching the authentication configuration, and to fetch the access tokens.
 *
 * @param confAddress Location to retrieve authentication configuration from. Must be a HTTP address that returns a JSON response.
 * @param confClient HTTP client used to retrieve authentication configuration.
 * @param authClient HTTP client used to retrieve tokens.
 * @param authTypeField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 * @param audienceField The field name to look up in the JSON response from the confAddress for `tokenFetcher.audience`.
 * @param issuerDomainField The field name to look up in the JSON response from the confAddress for `tokenFetcher.issuerDomainField`.
 * @param tokenPathField The field name to look up in the JSON response from the confAddress for `tokenFetcher.tokenPathField`.
 * @param requestContentType The content type required for the response. Defaults to application/json for Auth0 and application/x-www-form-urlencoded for Azure.
 * @param createBody a callback to turn the <*>RequestData into a string. By default will handle types for Azure and Auth0 as per requestContentType.
 *
 * @returns: A `ZepbenTokenFetcher` if the server reported authentication was configured, otherwise None.
 */
fun createTokenFetcher(
    confAddress: String,
    confClient: HttpClient,
    authClient: HttpClient,
    authTypeField: String = "authType",
    audienceField: String = "audience",
    issuerDomainField: String = "issuerDomain",
    tokenPathField: String = "tokenPath",
    requestContentType: String? = null,
    createBody: ((JsonObject) -> String)? = null,
): ZepbenTokenFetcher? {
    val request = HttpRequest.newBuilder().uri(URI(confAddress)).GET().build()
    val response = confClient.send(request, HttpResponse.BodyHandlers.ofString())
    if (response.statusCode() == StatusCode.OK.code) {
        try {
            val authConfigJson = Json.decodeValue(response.body()) as JsonObject
            val authMethod = AuthMethod.valueOf(authConfigJson.getString(authTypeField))
            if (authMethod != AuthMethod.NONE) {
                return ZepbenTokenFetcher(
                    audience = authConfigJson.getString(audienceField),
                    issuerDomain = authConfigJson.getString(issuerDomainField),
                    authMethod = authMethod,
                    client = authClient,
                    requestContentType = contentType(authMethod, requestContentType),
                    tokenPath = authConfigJson.getString(tokenPathField),
                    createBody = createRequestBody(authMethod, createBody)
                ).also {
                    if (it.authMethod == AuthMethod.AZURE) {
                        it.tokenRequestData.put("scope", "${it.audience}/.default")
                        it.refreshRequestData.put("scope", "${it.audience}/.default")
                    }
                }
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

private fun contentType(authMethod: AuthMethod, requestContentType: String?): String {
    if (!requestContentType.isNullOrEmpty())
        return requestContentType

    return if (authMethod == AuthMethod.AZURE)
        "application/x-www-form-urlencoded"
    else "application/json"
}

private fun createRequestBody(authMethod: AuthMethod, createBody: ((JsonObject) -> String)?): (JsonObject) -> String {
    if (createBody != null)
        return createBody

    return if (authMethod == AuthMethod.AZURE)
        { it -> it.joinToString("&") { m -> "${m.key}=${m.value}" } }
    else { it -> it.toString() }
}

/**
 * Helper method to fetch auth related configuration from `confAddress` and create a `ZepbenTokenFetcher`.
 * You may use `verififyCertificates` to specify whether to verify the certificates for the domains serving the
 * authentication configuration and the authentication provider.
 *
 * @param confAddress Location to retrieve authentication configuration from. Must be a HTTP address that returns a JSON response.
 * @param verifyCertificates: Whether to verify the certificate when making HTTPS requests. Note you should only use a trusted server
 *                            and never set this to False in a production environment.
 * @param authTypeField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 * @param audienceField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 * @param issuerDomainField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 *
 * @returns: A `ZepbenTokenFetcher` if the server reported authentication was configured, otherwise None.
 */
fun createTokenFetcher(
    confAddress: String,
    verifyCertificates: Boolean,
    authTypeField: String = "authType",
    audienceField: String = "audience",
    issuerDomainField: String = "issuerDomain",
    tokenPathField: String = "tokenPath",
) = createTokenFetcher(
    confAddress,
    if (verifyCertificates) HttpClient.newHttpClient() else HttpClient.newBuilder().sslContext(SSLContextUtils.allTrustingSSLContext()).build(),
    if (verifyCertificates) HttpClient.newHttpClient() else HttpClient.newBuilder().sslContext(SSLContextUtils.allTrustingSSLContext()).build(),
    authTypeField,
    audienceField,
    issuerDomainField,
    tokenPathField
)

/**
 * Helper method to fetch auth related configuration from `confAddress` and create a `ZepbenTokenFetcher`.
 * You may use `confCAFilename` and `authCAFilename` to specify the CAs used to verify the certificates for the domains serving the
 * authentication configuration and the authentication provider.
 *
 * @param confAddress Location to retrieve authentication configuration from. Must be a HTTP address that returns a JSON response.
 * @param confCAFilename Filename of X.509 CA certificate used to verify HTTPS responses from configuration service. Leave as null to use system CAs.
 * @param authCAFilename Filename of X.509 CA certificate used to verify HTTPS responses from token service. Leave as null to use system CAs.
 * @param authTypeField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 * @param audienceField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 * @param issuerDomainField The field name to look up in the JSON response from the confAddress for `tokenFetcher.authMethod`.
 * @param tokenPathField The field name for token fetch endpoint
 * @param verifyCertificates: Whether to verify the certificate when making HTTPS requests. Note you should only use a trusted server
 *                            and never set this to False in a production environment.
 *
 * @returns: A `ZepbenTokenFetcher` if the server reported authentication was configured, otherwise None.
 */
fun createTokenFetcher(
    confAddress: String,
    confCAFilename: String? = null,
    authCAFilename: String? = null,
    authTypeField: String = "authType",
    audienceField: String = "audience",
    issuerDomainField: String = "issuerDomain",
    tokenPathField: String = "tokenPath",
    verifyCertificates: Boolean = true
) = createTokenFetcher(
    confAddress,
    confCAFilename?.let {
        HttpClient.newBuilder().sslContext(SSLContextUtils.singleCACertSSLContext(it)).build()
    } ?: if (verifyCertificates) HttpClient.newHttpClient() else HttpClient.newBuilder().sslContext(SSLContextUtils.allTrustingSSLContext()).build() ,
    authCAFilename?.let {
        HttpClient.newBuilder().sslContext(SSLContextUtils.singleCACertSSLContext(it)).build()
    } ?: if (verifyCertificates) HttpClient.newHttpClient() else HttpClient.newBuilder().sslContext(SSLContextUtils.allTrustingSSLContext()).build() ,
    authTypeField,
    audienceField,
    issuerDomainField,
    tokenPathField
)