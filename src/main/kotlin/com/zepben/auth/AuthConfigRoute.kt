/*
 * Copyright 2020 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth

import com.zepben.vertxutils.routing.Respond
import com.zepben.vertxutils.routing.Route
import com.zepben.vertxutils.routing.RouteVersion
import com.zepben.vertxutils.routing.VersionableRoute
import io.netty.handler.codec.http.HttpResponseStatus
import io.vertx.core.Handler
import io.vertx.core.http.HttpMethod
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext

private data class AuthConfigResponse(val aud: String, val dom: String, val alg: String)

fun routeFactory(availableRoute: AvailableRoute, audience: String, domain: String, algorithm: String = "RS256"): Route =
    when (availableRoute) {
        AvailableRoute.AUTH_CONFIG ->
            Route.builder()
                .method(HttpMethod.GET)
                .path("/auth")
                .addHandler(AuthConfigRoute(audience, domain, algorithm))
                .build()
        else -> throw IllegalArgumentException("Invalid Route")
    }

enum class AvailableRoute(private val rv: RouteVersion) : VersionableRoute {
    AUTH_CONFIG(RouteVersion.since(2));

    override fun routeVersion(): RouteVersion {
        return rv
    }
}

class AuthConfigRoute(audience: String, domain: String, algorithm: String) : Handler<RoutingContext> {
    private val json: JsonObject = JsonObject.mapFrom(AuthConfigResponse(audience, domain, algorithm))

    override fun handle(event: RoutingContext?) {
        Respond.withJson(event, HttpResponseStatus.OK, json.encode())
    }
}
