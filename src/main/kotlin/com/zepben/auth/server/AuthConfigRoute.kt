/*
 * Copyright 2023 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth.server

import com.zepben.auth.common.AuthMethod
import com.zepben.vertxutils.routing.Respond
import com.zepben.vertxutils.routing.Route
import com.zepben.vertxutils.routing.RouteVersion
import com.zepben.vertxutils.routing.VersionableRoute
import io.netty.handler.codec.http.HttpResponseStatus
import io.vertx.core.Handler
import io.vertx.core.http.HttpMethod
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext

private data class AuthConfigResponse(
    val authType: AuthMethod,
    val issuerDomain: String,
    val audience: String,
    val tokenPath: String,
    val algorithm: String = "RS256"
)

fun routeFactory(
    availableRoute: AvailableRoute,
    audience: String,
    domain: String,
    tokenPath: String,
    authType: AuthMethod = AuthMethod.AUTH0,
    algorithm: String = "RS256"
): Route =
    when (availableRoute) {
        AvailableRoute.AUTH_CONFIG ->
            Route.builder()
                .method(HttpMethod.GET)
                .path("/auth")
                .addHandler(AuthConfigRoute(audience, domain, tokenPath, authType))
                .build()

        else -> throw IllegalArgumentException("Invalid Route")
    }

enum class AvailableRoute(private val rv: RouteVersion) : VersionableRoute {
    AUTH_CONFIG(RouteVersion.since(2));

    override fun routeVersion(): RouteVersion {
        return rv
    }
}

class AuthConfigRoute(audience: String, domain: String, tokenPath: String, authType: AuthMethod, algorithm: String = "RS256") : Handler<RoutingContext> {

    private val json: JsonObject = JsonObject.mapFrom(AuthConfigResponse(authType, domain, audience, tokenPath, algorithm))

    override fun handle(event: RoutingContext) {
        Respond.withJson(event, HttpResponseStatus.OK, json.encode())
    }
}
