/*
 * Copyright 2023 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth.server.grpc

import com.auth0.jwt.interfaces.DecodedJWT
import com.zepben.auth.common.StatusCode
import com.zepben.auth.server.AuthResponse
import com.zepben.auth.server.JWTAuthoriser
import com.zepben.auth.server.TokenAuthenticator
import io.grpc.*
import io.grpc.Metadata.ASCII_STRING_MARSHALLER


val AUTHORIZATION_METADATA_KEY: Metadata.Key<String> = Metadata.Key.of("Authorization", ASCII_STRING_MARSHALLER)
const val BEARER_TYPE = "Bearer"

fun statusCodeToStatus(statusCode: StatusCode): Status =
    when (statusCode) {
        StatusCode.OK -> Status.OK
        StatusCode.PERMISSION_DENIED -> Status.PERMISSION_DENIED
        StatusCode.UNAUTHENTICATED -> Status.UNAUTHENTICATED
        StatusCode.UNKNOWN -> Status.UNKNOWN
        else -> Status.UNKNOWN
    }

fun authRespToGrpcAuthResp(response: AuthResponse): GrpcAuthResp =
    GrpcAuthResp(
        statusCodeToStatus(response.statusCode).withDescription(response.message).withCause(response.cause)
    )

data class GrpcAuthResp(val status: Status, val token: DecodedJWT? = null)

/**
 * Intercepts, authenticates, and authorises gRPC calls.
 *
 * @property tokenAuthenticator The [TokenAuthenticator] to use for authenticating tokens.
 * @param requiredScopes A map of gRPC descriptors (fullMethodName) to their corresponding required scopes. If an empty set of scopes is provided, no authorisation
 * is necessary for the provided descriptor.
 * @param permissionsKey The key to use when looking up claims in the token.
 * @property authorise Callback to authorise a taken. Will be provided with the gRPC method name as per [serverCall.methodDescriptor.fullMethodName] and the JWT.
 * Must return a [GrpcAuthResp] with a valid status. By default will use [requiredScopes] and [permissionsKey] to determine authorisation.
 * If using the default implementation [requiredScopes] must not be null, and it must contain a valid claim for every possible gRPC serviceName.
 */
class AuthInterceptor(
    private val tokenAuthenticator: TokenAuthenticator,
    requiredScopes: Map<String, Set<String>>?,
    permissionsKey: String = "permissions",
    private val authorise: (String, DecodedJWT) -> GrpcAuthResp = { serviceName, token ->
        requiredScopes!![serviceName]?.let { claims ->
            authRespToGrpcAuthResp(JWTAuthoriser.authorise(token, claims, permissionsKey))
        }
            ?: GrpcAuthResp(Status.UNAUTHENTICATED.withDescription("Server has not defined a permission scope for ${serviceName}. This is a bug, contact the developers."))
    }
) : ServerInterceptor {

    override fun <ReqT, RespT> interceptCall(
        serverCall: ServerCall<ReqT, RespT>,
        metadata: Metadata,
        serverCallHandler: ServerCallHandler<ReqT, RespT>?
    ): ServerCall.Listener<ReqT> {
        val value = metadata[AUTHORIZATION_METADATA_KEY]
        val authResp = if (value == null) {
            GrpcAuthResp(Status.UNAUTHENTICATED.withDescription("Authorization token is missing"))
        } else if (!value.startsWith(BEARER_TYPE)) {
            GrpcAuthResp(Status.UNAUTHENTICATED.withDescription("Unknown authorization type"))
        } else {
            val r = tokenAuthenticator.authenticate(value.substring(BEARER_TYPE.length).trim { it <= ' ' })
            if (r.statusCode === StatusCode.OK)
                authorise(serverCall.methodDescriptor.fullMethodName!!, r.token!!)
            else
                GrpcAuthResp(statusCodeToStatus(r.statusCode).withDescription(r.message).withCause(r.cause))
        }

        if (authResp.status === Status.OK) {
            val ctx: Context = Context.current()
            return Contexts.interceptCall(ctx, serverCall, metadata, serverCallHandler)
        }
        serverCall.close(authResp.status, Metadata())
        return object : ServerCall.Listener<ReqT>() {} // no-op
    }
}


