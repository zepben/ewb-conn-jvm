/*
 * Copyright 2023 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth.server.vertx

import com.auth0.jwt.interfaces.DecodedJWT
import com.zepben.auth.common.StatusCode
import com.zepben.auth.server.JWTAuthoriser
import io.vertx.core.AsyncResult
import io.vertx.core.Future
import io.vertx.core.Handler
import io.vertx.core.json.JsonObject
import io.vertx.core.shareddata.impl.ClusterSerializable
import io.vertx.ext.auth.AbstractUser
import io.vertx.ext.auth.AuthProvider


/**
 *
 */
class User(private val jwt: DecodedJWT) : AbstractUser(), ClusterSerializable {

    override fun doIsPermitted(claims: String?, resultHandler: Handler<AsyncResult<Boolean>>) {
        if (claims.isNullOrEmpty()) {
            resultHandler.handle(Future.failedFuture("No permission was specified"))
            return
        }

        val resp = JWTAuthoriser.authorise(jwt, claims)
        if (resp.statusCode === StatusCode.OK)
            resultHandler.handle(Future.succeededFuture(true))
        else {
            resultHandler.handle(Future.succeededFuture(false))
        }
    }

    override fun setAuthProvider(authProvider: AuthProvider?) {
        throw NotImplementedError()
    }


    override fun principal() = JsonObject(mapOf("jwt" to jwt))
}
