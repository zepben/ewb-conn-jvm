package com.zepben.auth.client

import com.zepben.auth.common.StatusCode
import com.zepben.testutils.exception.ExpectException.Companion.expect
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.hamcrest.MatcherAssert.assertThat
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.URI
import java.net.URISyntaxException
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.http.HttpResponse.BodyHandler

class AuthProviderConfigTest {

    val handler = mockk<BodyHandler<String>>()
    val response = mockk<HttpResponse<String>> {
        every { statusCode() } returns StatusCode.OK.code
        every { body() } returns "{}"
    }
    val client = mockk<HttpClient> {
        every { send(any(), handler) } returns response
    }

    @Test
    fun `handles handles issuers with and without slashes`(){
        var issuer = "https://some-issuer/"

        fetchProviderDetails(issuer, client, handler)
        verify {
            client.send(HttpRequest.newBuilder().uri(URI("https://some-issuer/.well-known/openid-configuration")).GET().build(), handler)
        }

        issuer = "https://some-issuer"

        fetchProviderDetails(issuer, client, handler)
        verify {
            client.send(HttpRequest.newBuilder().uri(URI("https://some-issuer/.well-known/openid-configuration")).GET().build(), handler)
        }
    }
}
