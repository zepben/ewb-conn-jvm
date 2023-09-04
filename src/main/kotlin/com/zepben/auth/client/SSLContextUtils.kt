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


package com.zepben.auth.client

import java.io.FileInputStream
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

object SSLContextUtils {
    /**
     * Trust manager that does not check certificates.
     */
    private val allTrustingTrustManager = object: X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    /**
     * Used to override default HTTPS security for HttpsClient.
     */
    fun allTrustingSSLContext(): SSLContext {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(emptyArray(), arrayOf(allTrustingTrustManager), SecureRandom())
        return sslContext
    }

    /**
     * Make SSLContext that trusts a single X.509 CA certificate.
     */
    fun singleCACertSSLContext(caCertFilename: String): SSLContext {
        val cf = CertificateFactory.getInstance("X.509")
        val caCert = cf.generateCertificates(FileInputStream(caCertFilename))

        val ks = KeyStore.getInstance(KeyStore.getDefaultType())
        ks.load(null) // Initialise to empty keystore
        caCert.forEachIndexed { i, it ->
           ks.setCertificateEntry("caCert$i", it)
        }

        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(ks)

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(emptyArray(), tmf.trustManagers, SecureRandom())
        return sslContext
    }
}