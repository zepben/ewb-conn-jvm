/*
 * Copyright 2022 Zeppelin Bend Pty Ltd
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.zepben.auth.common

class MultiAuthException(val summary: String, val authExceptions: List<AuthException>): Exception(run {
    val messageBuilder = StringBuilder(summary)
    authExceptions.mapNotNull { it.message }.joinTo(messageBuilder, prefix = "\n\t", separator = "\n\t")
    messageBuilder.toString()
})