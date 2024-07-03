/*
 * Copyright 2024 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth.server

import com.zepben.auth.client.ProviderDetails

data class TrustedIssuer(
    val issuerDomain: String,
    val providerDetails: ProviderDetails
)
