// Copyright 2019 Zeppelin Bend Pty Ltd
// This file is part of zepben-auth.
//
// zepben-auth is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// zepben-auth is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with zepben-auth.  If not, see <https://www.gnu.org/licenses/>.


package com.zepben.auth.server

import com.auth0.jwt.interfaces.DecodedJWT
import com.zepben.auth.common.StatusCode

object JWTAuthoriser {

    /**
     * Authorise a JWT.
     * This function will check that a JWT has the required claims. The claims will be extracted from "permissions" (Auth0) or "roles" (EntraID), if "permissions" field is missing.
     *
     * @param token The JWT
     * @param requiredClaim The claim to authorise.
     */
    @JvmStatic
    fun authorise(token: DecodedJWT, requiredClaim: String): AuthResponse {
        return authorise(token, setOf(requiredClaim))
    }

    /**
     * Authorise a JWT.
     * This function will check that a JWT has all the [requiredClaims]. The claims will be extracted from "permissions" (Auth0) or "roles" (EntraID), if "permissions" field is missing.
     *
     * @param token The JWT
     * @param requiredClaims The claims to authorise. If empty all tokens will be authorised.
     */
    @JvmStatic
    fun authorise(token: DecodedJWT, requiredClaims: Set<String>): AuthResponse {
        if (requiredClaims.isEmpty())
            return AuthResponse(StatusCode.OK)
        val permissions = run {
            token.getClaim("permissions").asList(String::class.java) ?: token.getClaim("roles").asList(String::class.java) ?: emptyList()
        }.toHashSet()
        if (permissions.intersect(requiredClaims).size == requiredClaims.size)
            return AuthResponse(StatusCode.OK)
        return AuthResponse(
            StatusCode.UNAUTHENTICATED,
            "Token was missing a required claim. Had [${permissions.joinToString(", ")}] but needed [${requiredClaims.joinToString(", ")}]"
        )
    }
}
