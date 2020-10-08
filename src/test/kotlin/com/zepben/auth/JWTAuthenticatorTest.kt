/*
 * Copyright 2020 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth

import com.auth0.jwt.exceptions.*
import com.zepben.auth.JWTAuthoriser.authorise
import com.zepben.testutils.auth.*
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.hamcrest.Matchers.instanceOf
import org.junit.jupiter.api.Test

class JWTAuthenticatorTest {

    @Test
    fun testAuth() {
        var ta = JWTAuthenticator("https://fake-aud/", "issuer", MockJwksUrlProvider())
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

        ta = JWTAuthenticator("https://wrong-aud/", "issuer", MockJwksUrlProvider())
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
}



