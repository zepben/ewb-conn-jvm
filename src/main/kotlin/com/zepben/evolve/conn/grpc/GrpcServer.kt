/*
 * Copyright 2020 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.evolve.conn.grpc

import com.zepben.auth.grpc.AuthInterceptor
import io.grpc.Server
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContext
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContextBuilder
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Base class that can be used to create a gRPC server with the following configured:
 * - TLS
 * - Authentication (via an interceptor)
 *
 * @property port The port to listen on
 * @param sslContextConfig configured used to set up the ssl context for the server
 * @param authInterceptor interceptor registered to handle authentication of clients
 */
abstract class GrpcServer(
    val port: Int,
    sslContextConfig: SslContextConfig? = null,
    authInterceptor: AuthInterceptor? = null
) {
    /**
     * The server builder to configure your server instance
     */
    protected val serverBuilder: NettyServerBuilder = NettyServerBuilder.forPort(port)

    /**
     * The gRPC server instance.
     * On first access to this property the server instance is instantiated by building [serverBuilder].
     */
    protected val server: Server by lazy { serverBuilder.build() }

    init {
        createSslContext(sslContextConfig)?.let {
            serverBuilder.sslContext(it)
        }

        if (authInterceptor != null) {
            serverBuilder.intercept(authInterceptor)
        }
    }

    open fun start() {
        server.start()
        Runtime.getRuntime().addShutdownHook(Thread { stop() })
    }

    open fun stop() {
        server.shutdown()
    }

    fun blockUntilShutdown() {
        server.awaitTermination()
    }

    fun blockUntilShutdown(timeout: Long, unit: TimeUnit) {
        server.awaitTermination(timeout, unit)
    }

    /**
     * Create an SSLContext for use with the gRPC server.
     * @return null if a private key or cert chain are not provided, otherwise an SSLContext with the provided
     * credentials.
     */
    private fun createSslContext(
        config: SslContextConfig? = null
    ): SslContext? {
        if (config == null)
            return null

        with (config) {
            if (privateKeyFilePath.isNullOrBlank() || certChainFilePath.isNullOrBlank())
                return null

            val sslClientContextBuilder = SslContextBuilder.forServer(
                File(certChainFilePath),
                File(privateKeyFilePath)
            )
            if (!trustCertCollectionFilePath.isNullOrBlank()) {
                sslClientContextBuilder.trustManager(File(trustCertCollectionFilePath))
                sslClientContextBuilder.clientAuth(clientAuth)
            }

            return GrpcSslContexts.configure(sslClientContextBuilder).build()
        }
    }
}
