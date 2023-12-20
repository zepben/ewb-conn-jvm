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
import com.zepben.testutils.exception.ExpectException.Companion.expect
import com.zepben.vertxutils.testing.TestHttpServer
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.hamcrest.CoreMatchers.notNullValue
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.core.IsEqual.equalTo
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.*
import org.mockito.kotlin.mock
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpRequest.BodyPublishers
import java.net.http.HttpResponse
import javax.net.ssl.SSLContext

internal class ZepbenTokenFetcherTest {

    private lateinit var server: TestHttpServer
    private var port = 8080

    private val client = mock<HttpClient>()
    private val response = mock<HttpResponse<String>>()

    private val secureSSLContext = mock<SSLContext>()
    private val secureConfSSLContext = mock<SSLContext>()
    private val secureAuthSSLContext = mock<SSLContext>()
    private val insecureSSLContext = mock<SSLContext>()

    private val secureClient = mock<HttpClient>()
    private val secureConfClient = mock<HttpClient>()
    private val secureAuthClient = mock<HttpClient>()
    private val insecureClient = mock<HttpClient>()

    private val secureTokenFetcher = mock<ZepbenTokenFetcher>()
    private val insecureTokenFetcher = mock<ZepbenTokenFetcher>()

    @BeforeEach
    fun beforeEach() {
        server = TestHttpServer()
        port = server.listen()
        doReturn(response).`when`(client).send(any(), any<HttpResponse.BodyHandler<String>>())

        mockkObject(SSLContextUtils)
        every { SSLContextUtils.allTrustingSSLContext() } returns insecureSSLContext
        every { SSLContextUtils.singleCACertSSLContext("confCAFilename") } returns secureConfSSLContext
        every { SSLContextUtils.singleCACertSSLContext("authCAFilename") } returns secureAuthSSLContext

        mockkStatic(HttpClient::class)
        every { HttpClient.newHttpClient() } returns secureClient
        every { HttpClient.newBuilder().sslContext(insecureSSLContext).build() } returns insecureClient
        every { HttpClient.newBuilder().sslContext(secureConfSSLContext).build() } returns secureConfClient
        every { HttpClient.newBuilder().sslContext(secureAuthSSLContext).build() } returns secureAuthClient
    }

    @AfterEach
    fun afterEach() {
        server.close()
        unmockkAll()
    }

    @Test
    fun testCreateTokenFetcherSuccess() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn(
            "{\"authType\": \"OAUTH\", \"audience\": \"test_audience\", \"issuerDomain\": \"test_issuer\", \"tokenPath\": \"/oauth/token\"}"
        ).`when`(response).body()

        val tokenFetcher = createTokenFetcher("https://testaddress", confClient = client, authClient = client)
        verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
        assertThat(tokenFetcher?.audience, equalTo("test_audience"))
        assertThat(tokenFetcher?.issuerDomain, equalTo("test_issuer"))
    }

    @Test
    fun testCreateTokenFetcherNoTokenPath() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn(
            "{\"authType\": \"OAUTH\", \"audience\": \"test_audience\", \"issuerDomain\": \"test_issuer\"}"
        ).`when`(response).body()

        val tokenFetcher = createTokenFetcher("https://testaddress", confClient = client, authClient = client)
        verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
        assertThat(tokenFetcher?.audience, equalTo("test_audience"))
        assertThat(tokenFetcher?.issuerDomain, equalTo("test_issuer"))
    }

    @Test
    fun testCreateTokenFetcherLowercaseAuthType() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn(
            "{\"authType\": \"oauth\", \"audience\": \"test_audience\", \"issuerDomain\": \"test_issuer\", \"tokenPath\": \"/oauth/token\"}"
        ).`when`(response).body()

        val tokenFetcher = createTokenFetcher("https://testaddress", confClient = client, authClient = client)
        verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
        assertThat(tokenFetcher?.authMethod, equalTo(AuthMethod.OAUTH))
    }

    @Test
    fun testCreateTokenFetcherNoAuth() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn(
            "{\"authType\": \"NONE\", \"audience\": \"\", \"issuerDomain\": \"\"}"
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
            .exception
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
            .exception
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
            .exception
            .apply {
                verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
                assertThat(statusCode, equalTo(StatusCode.OK.code))
            }
    }

    @Test
    fun testCreateTokenFetcherManagedIdentity() {
        val tokenFetcher = createTokenFetcherManagedIdentity("https://testaddress")
        assertThat(tokenFetcher, notNullValue())
        assertThat(tokenFetcher.authMethod, equalTo(AuthMethod.AZURE))
    }

    @Test
    fun testFetchTokenSuccessful() {
        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("{\"access_token\":\"$TOKEN\", \"token_type\":\"Bearer\"}").`when`(response).body()

        val tokenFetcher = ZepbenTokenFetcher(
            audience = "test_audience",
            issuerDomain = "testissuer.com.au",
            authMethod = AuthMethod.OAUTH,
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
            authMethod = AuthMethod.OAUTH,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client
        )
        verify(client, never()).send(any(), any<HttpResponse.BodyHandler<String>>())
        expect {
            tokenFetcher.fetchToken()
        }.toThrow(AuthException::class.java)
            .withMessage("Token fetch failed, Error was: 404 - test text")
            .exception
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
            authMethod = AuthMethod.OAUTH,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client
        )
        verify(client, never()).send(any(), any<HttpResponse.BodyHandler<String>>())
        expect {
            tokenFetcher.fetchToken()
        }.toThrow(AuthException::class.java)
            .withMessage("Response did not contain valid JSON - response was: test text")
            .exception
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
            authMethod = AuthMethod.OAUTH,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client
        )
        verify(client, never()).send(any(), any<HttpResponse.BodyHandler<String>>())
        expect {
            tokenFetcher.fetchToken()
        }.toThrow(AuthException::class.java)
            .withMessage("Response was not a JSON object - response was: [\"test text\"]")
            .exception
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
            authMethod = AuthMethod.OAUTH,
            issuerProtocol = "https",
            tokenPath = "/fake/path",
            client = client
        )
        verify(client, never()).send(any(), any<HttpResponse.BodyHandler<String>>())
        expect {
            tokenFetcher.fetchToken()
        }.toThrow(AuthException::class.java)
            .withMessage("Access Token absent in token response - Response was: {\"test\":\"fail\"}")
            .exception
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

        mockStatic(BodyPublishers::class.java, CALLS_REAL_METHODS).use { bodyPublishers ->
            val tokenFetcher = ZepbenTokenFetcher(
                audience = "test_audience",
                issuerDomain = "testissuer.com.au",
                authMethod = AuthMethod.OAUTH,
                issuerProtocol = "https",
                tokenPath = "/fake/path",
                client = client,
                refreshToken = "test_refresh_token"
            )
            verify(client, never()).send(any(), any<HttpResponse.BodyHandler<String>>())
            val token = tokenFetcher.fetchToken()
            verify(client).send(any(), any<HttpResponse.BodyHandler<String>>())
            bodyPublishers.verify { BodyPublishers.ofString(matches("\"refresh_token\"\\s*:\\s*\"test_refresh_token\"")) }
            assertThat(token, equalTo("Bearer $TOKEN"))
        }

    }

    @Test
    fun testConstructorWithVerifyCertificatesOption() {
        doReturn(response).`when`(secureClient).send(any(), any<HttpResponse.BodyHandler<String>>())
        doReturn(response).`when`(insecureClient).send(any(), any<HttpResponse.BodyHandler<String>>())

        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("{\"access_token\":\"$TOKEN\", \"token_type\":\"Bearer\"}").`when`(response).body()

        assertThat(
            ZepbenTokenFetcher("audience", "issuerDomain", AuthMethod.OAUTH, verifyCertificate = true).fetchToken(),
            equalTo("Bearer $TOKEN")
        )
        assertThat(
            ZepbenTokenFetcher("audience", "issuerDomain", AuthMethod.OAUTH, verifyCertificate = false).fetchToken(),
            equalTo("Bearer $TOKEN")
        )
    }

    @Test
    fun testConstructorWithCAFilename() {
        doReturn(response).`when`(secureAuthClient).send(any(), any<HttpResponse.BodyHandler<String>>())

        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("{\"access_token\":\"$TOKEN\", \"token_type\":\"Bearer\"}").`when`(response).body()

        assertThat(
            ZepbenTokenFetcher("audience", "issuerDomain", AuthMethod.OAUTH, caFilename = "authCAFilename").fetchToken(),
            equalTo("Bearer $TOKEN")
        )
    }

    @Test
    fun testConstructorWithDefaultTls() {
        doReturn(response).`when`(secureClient).send(any(), any<HttpResponse.BodyHandler<String>>())

        doReturn(StatusCode.OK.code).`when`(response).statusCode()
        doReturn("{\"access_token\":\"$TOKEN\", \"token_type\":\"Bearer\"}").`when`(response).body()

        assertThat(
            ZepbenTokenFetcher("audience", "issuerDomain", AuthMethod.OAUTH).fetchToken(),
            equalTo("Bearer $TOKEN")
        )
    }

    @Test
    fun testCreateTokenFetcherWithVerifyCertificatesOption() {
        mockkStatic("com.zepben.auth.client.ZepbenTokenFetcherKt")
        every {
            createTokenFetcher("confAddress", secureClient, secureClient, "authTypeField", "audienceField", "issuerDomainField")
        } returns secureTokenFetcher
        every {
            createTokenFetcher("confAddress", insecureClient, insecureClient, "authTypeField", "audienceField", "issuerDomainField")
        } returns insecureTokenFetcher

        assertThat(createTokenFetcher("confAddress", true, "authTypeField", "audienceField", "issuerDomainField"), equalTo(secureTokenFetcher))
        assertThat(createTokenFetcher("confAddress", false, "authTypeField", "audienceField", "issuerDomainField"), equalTo(insecureTokenFetcher))
    }

    @Test
    fun testCreateTokenFetcherWithCAFilenames() {
        mockkStatic("com.zepben.auth.client.ZepbenTokenFetcherKt")
        every {
            createTokenFetcher("confAddress", secureConfClient, secureAuthClient, "authTypeField", "audienceField", "issuerDomainField", any(), any(), any())
        } returns secureTokenFetcher

        assertThat(
            createTokenFetcher("confAddress", "confCAFilename", "authCAFilename", "authTypeField", "audienceField", "issuerDomainField", "", true) { _, _, _ ->
                HttpRequest.newBuilder().build()
            },
            equalTo(secureTokenFetcher)
        )
    }

    @Test
    fun testCreateTokenFetcherWithDefaultTls() {
        mockkStatic("com.zepben.auth.client.ZepbenTokenFetcherKt")
        every {
            createTokenFetcher("confAddress", secureClient, secureClient, "authTypeField", "audienceField", "issuerDomainField", any(), any(), any())
        } returns secureTokenFetcher

        assertThat(
                createTokenFetcher ("confAddress", authTypeField = "authTypeField", audienceField = "audienceField", issuerDomainField = "issuerDomainField", tokenPathField = "", verifyCertificates = true, requestBuilder = { _, _, _ -> HttpRequest.newBuilder().build() }),
        equalTo(secureTokenFetcher)
        )
    }

    @Test
    fun testNormalisationOfIssuerUrl() {
        var tokenFetcher = ZepbenTokenFetcher("some_aud", "https://some_domain", AuthMethod.AUTH0)
        assertThat(tokenFetcher.issuerURL, equalTo("https://some_domain/oauth/token"))
        tokenFetcher = ZepbenTokenFetcher("some_aud", "https://some_domain/", AuthMethod.AUTH0)
        assertThat(tokenFetcher.issuerURL, equalTo("https://some_domain/oauth/token"))
        tokenFetcher = ZepbenTokenFetcher("some_aud", "some_domain/", AuthMethod.AUTH0)
        assertThat(tokenFetcher.issuerURL, equalTo("https://some_domain/oauth/token"))
        tokenFetcher = ZepbenTokenFetcher("some_aud", "some_domain/", AuthMethod.AUTH0, tokenPath = "some/path")
        assertThat(tokenFetcher.issuerURL, equalTo("https://some_domain/some/path"))
        tokenFetcher = ZepbenTokenFetcher("some_aud", "some_domain/", AuthMethod.AUTH0, issuerProtocol = "http")
        assertThat(tokenFetcher.issuerURL, equalTo("http://some_domain/oauth/token"))
    }

}
