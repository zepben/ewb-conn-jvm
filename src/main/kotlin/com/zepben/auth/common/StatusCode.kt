// Copyright 2022 Zeppelin Bend Pty Ltd
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


package com.zepben.auth.common

enum class StatusCode(val code: Int) {
    // Successful
    OK(200),
    // Token was malformed
    MALFORMED_TOKEN(400),
    // Failed to authenticate
    UNAUTHENTICATED(403),
    // Failed to authenticate, token didn't have required claims
    PERMISSION_DENIED(403),
    // Resource/service not found
    NOT_FOUND(404),
    // All other errors
    UNKNOWN(500);

}