/*
 * Copyright 2020 Zeppelin Bend Pty Ltd
 * This file is part of Unknown.
 *
 * Unknown is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Unknown is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Unknown.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.zepben.evolve.conn.grpc

import io.grpc.netty.shaded.io.netty.handler.ssl.ClientAuth

data class SslContextConfig(
    val certChainFilePath: String? = null,
    val privateKeyFilePath: String? = null,
    val trustCertCollectionFilePath: String? = null,
    val clientAuth: ClientAuth = ClientAuth.OPTIONAL
)
