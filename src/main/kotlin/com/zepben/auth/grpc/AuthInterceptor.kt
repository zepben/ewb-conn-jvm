/*
 * Copyright 2020 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth.grpc

import com.auth0.jwt.interfaces.DecodedJWT
import com.zepben.auth.*
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

fun authRespToGrpcAuthResp(response: AuthResponse) =
    GrpcAuthResp(
        statusCodeToStatus(response.statusCode).withDescription(response.message).withCause(response.cause)
    )

data class GrpcAuthResp(val status: Status, val token: DecodedJWT? = null)

class AuthInterceptor(
    private val tokenAuthenticator: TokenAuthenticator,
    private val requiredScopes: Map<String, String>
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
                requiredScopes[serverCall.methodDescriptor.serviceName!!]?.let {
                    authRespToGrpcAuthResp(JWTAuthoriser.authorise(r.token!!, it))
                }
                    ?: GrpcAuthResp(Status.UNAUTHENTICATED.withDescription("Server has not defined a permission scope for ${serverCall.methodDescriptor.serviceName}. This is a bug, contact the developers."))
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


