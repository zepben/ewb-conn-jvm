/*
 * Copyright 2024 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth.server

import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkException
import com.auth0.jwk.UrlJwkProvider
import java.net.URI
import java.net.URL

fun trustedIssuerUrlJwkProvider(
    issuer: TrustedIssuer,
    urlJwkProviderProvider: (URL) -> UrlJwkProvider = { url -> UrlJwkProvider(url) }
) = urlJwkProviderProvider(URI(issuer.providerDetails.jwkUrl).toURL()).all.associateBy { it.id }

class JWKHolder(
    private val jwkProvider: (TrustedIssuer) -> Map<String, Jwk> = { issuer -> trustedIssuerUrlJwkProvider(issuer) }
) {
    private var keys: MutableMap<String, Map<String, Jwk>> = mutableMapOf()

    fun getKeyFromJwk(kid: String, issuer: TrustedIssuer): Jwk =
        keys[issuer.issuerDomain]?.get(kid)?: run {
            keys[issuer.issuerDomain] = jwkProvider(issuer)
            keys[issuer.issuerDomain]?.get(kid) ?: throw JwkException("Unable to find key $kid in jwk endpoint. Check your JWK URL.")
        }
}
