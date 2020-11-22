/*
 * Copyright 2020 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth

import com.zepben.testutils.vertx.TestHttpServer
import com.zepben.vertxutils.routing.RouteVersionUtils
import io.netty.handler.codec.http.HttpResponseStatus
import io.restassured.RestAssured
import io.vertx.core.json.JsonObject
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class AuthConfigRouteTest {
    private var server: TestHttpServer? = null
    private var port = 8080

    @BeforeEach
    fun before() {
        server = TestHttpServer().addRoutes(
            RouteVersionUtils.forVersion(
                AvailableRoute.values(),
                2
            ) { routeFactory(it, "test-auth-type", "test-issuer", "test-audience") }
        )
        port = server!!.listen()
    }

    @Test
    fun testHandle() {
        val expectedResponse: String = JsonObject().apply {
            put("authType", "test-auth-type")
            put("issuer", "test-issuer")
            put("audience", "test-audience")
        }.encode()

        val response = RestAssured.given()
            .port(port)["/auth"]
            .then()
            .statusCode(HttpResponseStatus.OK.code())
            .extract().body().asString()

        assertThat(response, equalTo(expectedResponse))
    }
}
