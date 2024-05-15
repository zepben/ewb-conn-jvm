/*
 * Copyright 2023 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth.server

import com.auth0.jwt.interfaces.DecodedJWT
import com.zepben.auth.common.StatusCode

object JWTAuthoriser {

    /**
     * Authorise a JWT.
     * This function will check that a JWT has the required claims. Claims will be extracted from the given [permissionsField].
     *
     * @param token The JWT
     * @param requiredClaim The claim to authorise.
     * @param permissionsField The field to extract claims from. Defaults to "permissions".
     */
    @JvmStatic
    fun authorise(token: DecodedJWT, requiredClaim: String, permissionsField: String = "permissions"): AuthResponse {
        val permissions = token.getClaim(permissionsField).asList(String::class.java).toHashSet()
        if (requiredClaim in permissions)
            return AuthResponse(StatusCode.OK)
        return AuthResponse(StatusCode.UNAUTHENTICATED, "Token was missing required claim $requiredClaim")
    }

    /**
     * Authorise a JWT.
     * This function will check that a JWT has all the [requiredClaims]. Claims will be extracted from the given [permissionsField].
     *
     * @param token The JWT
     * @param requiredClaims The claims to authorise. If empty all tokens will be authorised.
     * @param permissionsField The field to extract claims from. Defaults to "permissions".
     */
    @JvmStatic
    fun authorise(token: DecodedJWT, requiredClaims: Set<String>, permissionsField: String = "permissions"): AuthResponse {
        if (requiredClaims.isEmpty())
            return AuthResponse(StatusCode.OK)
        val permissions = token.getClaim(permissionsField).asList(String::class.java).toHashSet()
        if (permissions.intersect(requiredClaims).size == requiredClaims.size)
            return AuthResponse(StatusCode.OK)
        return AuthResponse(
            StatusCode.UNAUTHENTICATED,
            "Token was missing a required claim. Had [${permissions.joinToString(", ")}] but needed [${requiredClaims.joinToString(", ")}]"
        )
    }
}
