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
import com.zepben.testutils.exception.ExpectException
import io.mockk.every
import io.mockk.excludeRecords
import io.mockk.mockk
import io.mockk.verifySequence
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.jupiter.api.Test

class JWKHolderTest {

    private val jwk33 = mockk<Jwk>()
    private val jwk5006 = mockk<Jwk>()
    private val jwkCommonOne = mockk<Jwk>()
    private val jwkCommonTwo = mockk<Jwk>()

    private val trustedIssuerOne = mockk<TrustedIssuer> {
        every { issuerDomain } returns "one"
    }

    private val trustedIssuerTwo = mockk<TrustedIssuer> {
        every { issuerDomain } returns "two"
    }

    private val jwkProvider = mockk<(TrustedIssuer) -> Map<String, Jwk>>().also {
        every { it(trustedIssuerOne) } returns mapOf("keyId_33" to jwk33, "keyId_5006" to jwk5006, "common_key_id" to jwkCommonOne)
        every { it(trustedIssuerTwo) } returns mapOf("common_key_id" to jwkCommonTwo)
    }

    @Test
    fun `JWKHolder refreshes keys from issuer if kid not found in cache`() {
        val underTest = JWKHolder(jwkProvider)
        MatcherAssert.assertThat(underTest.getKeyFromJwk("keyId_33", trustedIssuerOne), Matchers.equalTo(jwk33))

        validateKeyRequests(
            listOf(
                KeyRequestCheck(trustedIssuerOne, jwkProvider, true),
            )
        )
    }

    @Test
    fun `JWKHolder takes key from cache if found`() {
        val underTest = JWKHolder(jwkProvider)
        MatcherAssert.assertThat(underTest.getKeyFromJwk("keyId_33", trustedIssuerOne), Matchers.equalTo(jwk33))
        MatcherAssert.assertThat(underTest.getKeyFromJwk("keyId_33", trustedIssuerOne), Matchers.equalTo(jwk33))

        validateKeyRequests(
            listOf(
                KeyRequestCheck(trustedIssuerOne, jwkProvider, true),
                KeyRequestCheck(trustedIssuerOne, jwkProvider, false),
            )
        )
    }

    @Test
    fun `JWKHolder handles kid collision`() {
        val underTest = JWKHolder(jwkProvider)

        MatcherAssert.assertThat(underTest.getKeyFromJwk("common_key_id", trustedIssuerOne), Matchers.equalTo(jwkCommonOne))
        MatcherAssert.assertThat(underTest.getKeyFromJwk("common_key_id", trustedIssuerTwo), Matchers.equalTo(jwkCommonTwo))
        MatcherAssert.assertThat(underTest.getKeyFromJwk("common_key_id", trustedIssuerOne), Matchers.equalTo(jwkCommonOne))

        validateKeyRequests(
            listOf(
                KeyRequestCheck(trustedIssuerOne, jwkProvider, true),
                KeyRequestCheck(trustedIssuerTwo, jwkProvider, true),
                KeyRequestCheck(trustedIssuerOne, jwkProvider, false),
            )
        )
    }

    @Test
    fun `JWKHolder handles no keys returned`() {
        every { jwkProvider(trustedIssuerOne) } returns emptyMap()

        val underTest = JWKHolder(jwkProvider)

        ExpectException.expect {
            underTest.getKeyFromJwk("keyId_34", trustedIssuerOne)
        }.toThrow<JwkException>().withMessage("Unable to find key keyId_34 in jwk endpoint. Check your JWK URL.")
        validateKeyRequest(trustedIssuerOne, jwkProvider, true)
    }

    @Test
    fun `JWKHolder throws on unable to find after refreshing cache`() {
        val underTest = JWKHolder(jwkProvider)
        ExpectException.expect {
            underTest.getKeyFromJwk("keyId_34", trustedIssuerOne)
        }.toThrow<JwkException>().withMessage("Unable to find key keyId_34 in jwk endpoint. Check your JWK URL.")

        validateKeyRequest(trustedIssuerOne, jwkProvider, true)
    }

    data class KeyRequestCheck(
        val trustedIssuer: TrustedIssuer,
        val provider: (TrustedIssuer) -> Map<String, Jwk>,
        val expectCacheRefresh: Boolean
    )

    private fun validateKeyRequests(requests: List<KeyRequestCheck>) {
        excludeRecords {
            requests.forEach {
                it.trustedIssuer.equals(any()) //this is from the answer selection... https://github.com/mockk/mockk/issues/577
            }
        }

        verifySequence {
            requests.forEach {
                it.trustedIssuer.issuerDomain
                if (it.expectCacheRefresh) {
                    it.trustedIssuer.issuerDomain
                    it.provider(it.trustedIssuer)
                    it.trustedIssuer.issuerDomain
                }
            }
        }
    }

    private fun validateKeyRequest(trustedIssuer: TrustedIssuer, jwkProvider: (TrustedIssuer) -> Map<String, Jwk>, expectCacheRefresh: Boolean) {
        validateKeyRequests(listOf(KeyRequestCheck(trustedIssuer, jwkProvider, expectCacheRefresh)))
    }
}
