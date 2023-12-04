/*
 * Copyright 2023 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth.server.vertx

import com.zepben.auth.*
import com.zepben.auth.common.StatusCode
import com.zepben.auth.server.TokenAuthenticator
import com.zepben.auth.server.asHttpException
import io.vertx.core.AsyncResult
import io.vertx.core.Future
import io.vertx.core.Handler
import io.vertx.core.json.JsonObject
import io.vertx.ext.auth.AuthProvider
import io.vertx.ext.auth.User
import io.vertx.kotlin.core.json.get

/**
 * An implementation of an [AuthProvider] that performs JWT authentication with the provided [tokenAuthenticator]
 *
 * @property tokenAuthenticator The Authenticator to use for for authentication.
 */
class JWTAuthProvider(private val tokenAuthenticator: TokenAuthenticator) : AuthProvider {

    /**
     * Authenticate a client based on the provided [authInfo].
     * @param A [JsonObject] with a "jwt" entry with the JWT for this client.
     */
    override fun authenticate(authInfo: JsonObject?, resultHandler: Handler<AsyncResult<User>>) {
        val token: String? = authInfo?.get("jwt")
        val resp = tokenAuthenticator.authenticate(token)
        if (resp.statusCode !== StatusCode.OK) {
            resultHandler.handle(Future.failedFuture(resp.asHttpException()))
            return
        }

        resp.token?.let { resultHandler.handle(Future.succeededFuture(User(it))) } ?: resultHandler.handle(
            Future.failedFuture("Token was missing on successful auth - this is a bug.")
        )
    }

}
