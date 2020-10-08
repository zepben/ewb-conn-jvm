/*
 * Copyright 2020 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth.grpc

import com.zepben.auth.JWTAuthenticator
import com.zepben.testutils.auth.MockJwksUrlProvider
import com.zepben.testutils.auth.MockServerCall
import com.zepben.testutils.auth.MockServerCallHandler
import com.zepben.testutils.auth.TOKEN
import io.grpc.Metadata
import io.grpc.Status
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.junit.jupiter.api.Test

const val write_network_scope = "write:network"

class AuthInterceptorTest {

    @Test
    fun testIntercept() {
        var ta = JWTAuthenticator("https://fake-aud/", "issuer", MockJwksUrlProvider())
        val requiredScopes = mapOf(
            "zepben.protobuf.np.NetworkProducer" to write_network_scope
        )
        val authInterceptor = AuthInterceptor(ta, requiredScopes)
        var sc = MockServerCall<Int, Int>({ status, _ ->
            assertThat(status!!.code, equalTo(Status.UNAUTHENTICATED.code))
            assertThat(status.description, equalTo("Authorization token is missing"))
        })
        authInterceptor.interceptCall(sc, Metadata(), null)

        val mdNotBearer = Metadata().apply { put(AUTHORIZATION_METADATA_KEY, "NotBearer ayyyyy") }
        sc = MockServerCall({ status, _ ->
            assertThat(status!!.code, equalTo(Status.UNAUTHENTICATED.code))
            assertThat(status.description, equalTo("Unknown authorization type"))
        })
        authInterceptor.interceptCall(sc, mdNotBearer, null)

        val mdWithBearer = Metadata().apply { put(AUTHORIZATION_METADATA_KEY, "Bearer $TOKEN") }
        sc = MockServerCall({ _, _ -> })
        var callWasMade = false
        val sch = MockServerCallHandler<Int, Int> { _, metadata ->
            // not really important assert - just to make sure no one balls'd up the test
            assertThat("Metadata had bearer token.", metadata.containsKey(AUTHORIZATION_METADATA_KEY))
            callWasMade = true
        }
        authInterceptor.interceptCall(sc, mdWithBearer, sch)
        assertThat(callWasMade, equalTo(true))

        callWasMade = false
        val mdWithBadBearer = Metadata().apply { put(AUTHORIZATION_METADATA_KEY, "Bearer aoeu") }
        sc = MockServerCall({ status, _ ->
            assertThat(status!!.code, equalTo(Status.UNAUTHENTICATED.code))
        })
        authInterceptor.interceptCall(sc, mdWithBadBearer, sch)
        assertThat(callWasMade, equalTo(false))
    }
}
