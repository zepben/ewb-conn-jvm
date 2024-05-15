// Copyright 2019 Zeppelin Bend Pty Ltd
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

package com.zepben.auth.server

import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkException
import com.auth0.jwk.UrlJwkProvider
import com.auth0.jwt.exceptions.*
import com.zepben.auth.common.StatusCode
import com.zepben.auth.server.JWTAuthoriser.authorise
import com.zepben.testutils.auth.*
import com.zepben.testutils.exception.ExpectException.expect
import io.mockk.every
import io.mockk.mockk
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.instanceOf
import org.junit.jupiter.api.Test

class JWTAuthenticatorTest {

    @Test
    fun testAuth() {
        var ta = JWTAuthenticator("https://fake-aud/", "https://issuer/", MockJwksUrlProvider())
        var authResp = ta.authenticate(TOKEN)
        assertThat(authResp.statusCode, equalTo(StatusCode.OK))
        val successfulToken = authResp.token!!
        authResp = authorise(successfulToken, "write:network")
        assertThat(authResp.statusCode, equalTo(StatusCode.OK))

        authResp = authorise(successfulToken, "bacon")
        assertThat(authResp.statusCode, equalTo(StatusCode.UNAUTHENTICATED))
        assertThat(authResp.message, equalTo("Token was missing required claim bacon"))

        authResp = ta.authenticate("broken")
        assertThat(authResp.statusCode, equalTo(StatusCode.UNAUTHENTICATED))
        assertThat(authResp.cause, instanceOf(JWTDecodeException::class.java))

        authResp = ta.authenticate(TOKEN_RS512)
        assertThat(authResp.statusCode, equalTo(StatusCode.UNAUTHENTICATED))
        assertThat(authResp.cause, instanceOf(AlgorithmMismatchException::class.java))

        authResp = ta.authenticate(TOKEN_BAD_SIG)
        assertThat(authResp.statusCode, equalTo(StatusCode.UNAUTHENTICATED))
        assertThat(authResp.cause, instanceOf(SignatureVerificationException::class.java))

        authResp = ta.authenticate(TOKEN_EXPIRED)
        assertThat(authResp.statusCode, equalTo(StatusCode.UNAUTHENTICATED))
        assertThat(authResp.cause, instanceOf(TokenExpiredException::class.java))

        ta = JWTAuthenticator("https://wrong-aud/", "https://issuer/", MockJwksUrlProvider())
        authResp = ta.authenticate(TOKEN)
        assertThat(authResp.statusCode, equalTo(StatusCode.PERMISSION_DENIED))
        assertThat(authResp.cause, instanceOf(InvalidClaimException::class.java))
        assertThat(authResp.message, equalTo("The Claim 'aud' value doesn't contain the required audience."))

        ta = JWTAuthenticator("https://fake-aud/", "wrong-issuer", MockJwksUrlProvider())
        authResp = ta.authenticate(TOKEN)
        assertThat(authResp.statusCode, equalTo(StatusCode.PERMISSION_DENIED))
        assertThat(authResp.cause, instanceOf(InvalidClaimException::class.java))
        assertThat(authResp.message, equalTo("The Claim 'iss' value doesn't match the required issuer."))
    }

    @Test
    fun `keys are updated when unknown key is provided`() {
        val jwk = Jwk("fakekid", "RSA", "RS256", "", emptyList(), "", emptyList(), "", attribs)
        val mockJWK = mockk<UrlJwkProvider> {
            every { all } returns listOf(jwk)
        }
        val ta = JWTAuthenticator("https://fake-aud/", "https://issuer/", mockJWK)

        assertThat(ta.getKeyFromJwk("fakekid"), equalTo(jwk))

        expect {
            ta.getKeyFromJwk("fakekey")
        }.toThrow(JwkException::class.java)
            .withMessage("Unable to find key fakekey in jwk endpoint. Check your JWK URL.")
    }
}
