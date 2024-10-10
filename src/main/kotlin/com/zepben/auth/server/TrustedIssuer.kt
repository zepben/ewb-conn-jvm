/*
 * Copyright 2024 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth.server

import com.zepben.auth.client.ProviderDetails
import com.zepben.auth.client.fetchProviderDetails

data class TrustedIssuer(
    val issuerDomain: String,
    private val providerDetailsProvider: (String) -> ProviderDetails = { fetchProviderDetails(issuerDomain) }
) {

    constructor(issuerDomain: String, providerDetails: ProviderDetails) : this(issuerDomain, { _ -> providerDetails } )

    val providerDetails: ProviderDetails by lazy {
        providerDetailsProvider(issuerDomain)
    }
}
