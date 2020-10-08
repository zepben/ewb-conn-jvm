/*
 * Copyright 2020 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth

import com.auth0.jwt.interfaces.DecodedJWT

object JWTAuthoriser {
    @JvmStatic
    fun authorise(token: DecodedJWT, requiredClaim: String): AuthResponse {
        val permissions = token.getClaim("permissions").asList(String::class.java).toHashSet()
        if (requiredClaim in permissions)
            return AuthResponse(StatusCode.OK)
        return AuthResponse(StatusCode.UNAUTHENTICATED, "Token was missing required claim $requiredClaim")
    }

    @JvmStatic
    fun authorise(token: DecodedJWT, requiredClaims: Set<String>): AuthResponse {
        val permissions = token.getClaim("permissions").asList(String::class.java).toHashSet()
        if (permissions.intersect(requiredClaims).size == requiredClaims.size)
            return AuthResponse(StatusCode.OK)
        return AuthResponse(
            StatusCode.UNAUTHENTICATED,
            "Token was missing a required claim. Had [${permissions.joinToString(", ")}] but needed [${requiredClaims.joinToString(
                ", "
            )}]"
        )
    }
}
