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

import com.zepben.auth.common.AuthException
import com.zepben.auth.common.AuthMethod
import com.zepben.auth.common.StatusCode
import com.zepben.testutils.auth.TOKEN
import com.zepben.testutils.exception.ExpectException.expect
import com.zepben.testutils.vertx.TestHttpServer
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.core.IsEqual.equalTo
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.*
import org.mockito.kotlin.mock
import java.net.http.HttpClient
import java.net.http.HttpResponse

internal class ZepbenTokenFetcherTest {
    private lateinit var server: TestHttpServer
    private var port = 8080

    private val client = mock<HttpClient>()
    private val response = mock<HttpResponse<String>>()

    @BeforeEach
    fun beforeEach() {
        server = TestHttpServer()
        port = server.listen()
        doReturn(response).`when`(client).send(any(), any<HttpResponse.BodyHandler<String>>())
    }

    @AfterEach
    fun afterEach() {
        server.close()
    }

    @Test
    fun testCreateTokenFetcherSuccess() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn(
            "{\"authType\": \"AUTH0\", \"audience\": \"test_audience\", \"issuer\": \"test_issuer\"}"
        ).`when`(response).body()

        val tokenFetcher = createTokenFetcher("https://testaddress", confClient = client, authClient = client)
        verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
        assertThat(tokenFetcher?.audience, equalTo("test_audience"))
        assertThat(tokenFetcher?.issuerDomain, equalTo("test_issuer"))
    }

    @Test
    fun testCreateTokenFetcherNoAuth() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn(
            "{\"authType\": \"NONE\", \"audience\": \"\", \"issuer\": \"\"}"
        ).`when`(response).body()

        val tokenFetcher = createTokenFetcher("https://testaddress", confClient = client, authClient = client)
        verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
        assertThat(tokenFetcher, equalTo(null))
    }

    @Test
    fun testCreateTokenFetcherBadResponse() {
        doReturn(StatusCode.NOT_FOUND.code).`when`(response).statusCode()
        doReturn("Not found").`when`(response).body()

        expect {
            createTokenFetcher("https://testaddress", confClient = client, authClient = client)
        }.toThrow(AuthException::class.java)
            .withMessage("https://testaddress responded with error: 404 - Not found")
            .exception()
            .apply {
                verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
                assertThat(statusCode, equalTo(StatusCode.NOT_FOUND.code))
            }
    }

    @Test
    fun testCreateTokenFetcherMissingJson() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("test text").`when`(response).body()

        expect {
            createTokenFetcher("https://testaddress", confClient = client, authClient = client)
        }.toThrow(AuthException::class.java)
            .withMessage("Expected JSON response from https://testaddress, but got: test text.")
            .exception()
            .apply {
                verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
                assertThat(statusCode, equalTo(StatusCode.OK.code))
            }
    }

    @Test
    fun testCreateTokenFetcherNonObjectJson() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("[\"authType\"]").`when`(response).body()

        expect {
            createTokenFetcher("https://testaddress", confClient = client, authClient = client)
        }.toThrow(AuthException::class.java)
            .withMessage("Expected JSON object from https://testaddress, but got: [\"authType\"].")
            .exception()
            .apply {
                verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
                assertThat(statusCode, equalTo(StatusCode.OK.code))
            }
    }

    @Test
    fun testFetchTokenSuccessful() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("{\"access_token\":\"$TOKEN\", \"token_type\":\"Bearer\"}").`when`(response).body()

        val tokenFetcher = ZepbenTokenFetcher(
            audience = "test_audience",
            issuerDomain = "testissuer.com.au",
            authMethod = AuthMethod.AUTH0,
            verifyCertificate = true,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client
        )
        verify(client, never()).send(any(), any<HttpResponse.BodyHandler<String>>())
        val token = tokenFetcher.fetchToken()
        verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
        assertThat(token, equalTo("Bearer $TOKEN"))
    }

    @Test
    fun testFetchTokenThrowsExceptionOnBadResponse() {
        doReturn(StatusCode.NOT_FOUND.code).`when`(response).statusCode()
        doReturn("test text").`when`(response).body()

        val tokenFetcher = ZepbenTokenFetcher(
            audience = "test_audience",
            issuerDomain = "testissuer.com.au",
            authMethod = AuthMethod.AUTH0,
            verifyCertificate = true,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client
        )
        verify(client, never()).send(any(), any<HttpResponse.BodyHandler<String>>())
        expect {
            tokenFetcher.fetchToken()
        }.toThrow(AuthException::class.java)
            .withMessage("Token fetch failed, Error was: 404 - test text")
            .exception()
            .apply {
                verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
                assertThat(statusCode, equalTo(StatusCode.NOT_FOUND.code))
            }
    }

    @Test
    fun testFetchTokenThrowsExceptionOnMissingJson() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("test text").`when`(response).body()

        val tokenFetcher = ZepbenTokenFetcher(
            audience = "test_audience",
            issuerDomain = "testissuer.com.au",
            authMethod = AuthMethod.AUTH0,
            verifyCertificate = true,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client
        )
        verify(client, never()).send(any(), any<HttpResponse.BodyHandler<String>>())
        expect {
            tokenFetcher.fetchToken()
        }.toThrow(AuthException::class.java)
            .withMessage("Response did not contain valid JSON - response was: test text")
            .exception()
            .apply {
                verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
                assertThat(statusCode, equalTo(StatusCode.OK.code))
            }
    }

    @Test
    fun testFetchTokenThrowsExceptionOnNonObjectJson() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("[\"test text\"]").`when`(response).body()

        val tokenFetcher = ZepbenTokenFetcher(
            audience = "test_audience",
            issuerDomain = "testissuer.com.au",
            authMethod = AuthMethod.AUTH0,
            verifyCertificate = true,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client
        )
        verify(client, never()).send(any(), any<HttpResponse.BodyHandler<String>>())
        expect {
            tokenFetcher.fetchToken()
        }.toThrow(AuthException::class.java)
            .withMessage("Response was not a JSON object - response was: [\"test text\"]")
            .exception()
            .apply {
                verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
                assertThat(statusCode, equalTo(StatusCode.OK.code))
            }
    }

    @Test
    fun testFetchTokenThrowsExceptionOnMissingAccessToken() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("{\"test\":\"fail\"}").`when`(response).body()

        val tokenFetcher = ZepbenTokenFetcher(
            audience = "test_audience",
            issuerDomain = "testissuer.com.au",
            authMethod = AuthMethod.AUTH0,
            verifyCertificate = true,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client
        )
        verify(client, never()).send(any(), any<HttpResponse.BodyHandler<String>>())
        expect {
            tokenFetcher.fetchToken()
        }.toThrow(AuthException::class.java)
            .withMessage("Access Token absent in token response - Response was: {\"test\":\"fail\"}")
            .exception()
            .apply {
                verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
                assertThat(statusCode, equalTo(StatusCode.OK.code))
            }
    }

    @Test
    fun testFetchTokenSuccessfulUsingRefresh() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn(
            "{\"access_token\":\"$TOKEN\", \"refresh_token\": \"test_refresh_token\", \"token_type\":\"Bearer\"}"
        ).`when`(response).body()

        val tokenFetcher = ZepbenTokenFetcher(
            audience = "test_audience",
            issuerDomain = "testissuer.com.au",
            authMethod = AuthMethod.AUTH0,
            verifyCertificate = true,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client,
            refreshToken = "test_refresh_token"
        )
        verify(client, never()).send(any(), any<HttpResponse.BodyHandler<String>>())
        val token = tokenFetcher.fetchToken()
        verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
        assertThat(token, equalTo("Bearer $TOKEN"))
    }
}