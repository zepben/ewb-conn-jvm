/*
 * Copyright 2020 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth.grpc

import com.zepben.auth.JWTAuthenticator
import com.zepben.evolve.conn.grpc.runServerCall
import com.zepben.testutils.auth.MockJwksUrlProvider
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
        val ta = JWTAuthenticator("https://fake-aud/", "issuer", MockJwksUrlProvider())
        val requiredScopes = mapOf(
            "zepben.protobuf.np.NetworkProducer" to write_network_scope
        )
        val authInterceptor = AuthInterceptor(ta, requiredScopes)

        runServerCall(authInterceptor,
            { status, _ ->
                assertThat(status!!.code, equalTo(Status.UNAUTHENTICATED.code))
                assertThat(status.description, equalTo("Authorization token is missing"))
            },
            null
        )

        runServerCall(authInterceptor,
            { status, _ ->
                assertThat(status!!.code, equalTo(Status.UNAUTHENTICATED.code))
                assertThat(status.description, equalTo("Unknown authorization type"))
            }, null, metadata = Metadata().apply { put(AUTHORIZATION_METADATA_KEY, "NotBearer ayyyyy") }
        )

        runServerCall(authInterceptor,
            { _, _ -> assert(true)},
            { sc, metadata -> assertThat("Metadata had bearer token.", metadata.containsKey(AUTHORIZATION_METADATA_KEY))
                sc.close(null, null)  // Close for some reason doesn't occur at any point on a successful auth, so we call it ourselves.
            },
            metadata = Metadata().apply { put(AUTHORIZATION_METADATA_KEY, "Bearer $TOKEN") }
        )

        runServerCall(authInterceptor,
            { status, _ ->
                assertThat(status!!.code, equalTo(Status.UNAUTHENTICATED.code))
            },
            { _, metadata -> assertThat("Metadata had bearer token.", metadata.containsKey(AUTHORIZATION_METADATA_KEY)) },
            metadata = Metadata().apply { put(AUTHORIZATION_METADATA_KEY, "Bearer aoeu") }
        )
    }
}
