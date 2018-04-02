/**********************************************************************************************
 * Project:     Approov
 * File:        CordovaApproovHttpPinningVerifier.java
 * Original:    Created on 7 Aug 2017 by barryo
 *
 * Copyright(c) 2018 by CriticalBlue Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 **********************************************************************************************/

package com.criticalblue.cordova.approov.http;

import com.criticalblue.attestationlibrary.ApproovAttestation;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLException;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * Inspired by “Android Security: SSL Pinning” by Matthew Dolan
 * https://medium.com/@appmattus/android-security-ssl-pinning-1db8acb6621e
 *
 * This is an example of how to implement Approov based Dynamic Pinning
 * on Android.
 *
 * This implementation of HostnameVerifier is intended to enhance the
 * HostnameVerifier your SSL implementation normally uses. The
 * HostnameVerifier passed into the constructor continues to be executed
 * when verify is called.
 */
public final class CordovaApproovHttpPinningVerifier implements HostnameVerifier {

    /** The HostnameVerifier you would normally be using. */
    private final HostnameVerifier delegate;

    /** Tag for log messages */
    private static final String TAG = "DYNAMIC_PINNING";

    /**
     * Construct a CordovaApproovHttpPinningVerifier which delegates
     * the initial verify to a user defined HostnameVerifier before
     * applying dynamic pinning on top.
     *
     * @param delegate The HostnameVerifier to apply before the Dynamic
     *                  pinning check. Typically this would be the class
     *                  used by your usual http library (i.e OkHttp) or
     *                  simply  javax.net.ssl.DefaultHostnameVerifier
     */
    public CordovaApproovHttpPinningVerifier(HostnameVerifier delegate) {
        this.delegate = delegate;
    }

    /**
     * Check the Approov SDK cached cert for this hostname
     * against the provided Leaf Cert.
     *
     * @param hostname Name of the host we are checking the cert for.
     * @param leafCert The leaf certificate of the chain provided by the
     *                  host we are connecting to. Typically this is the 0th
     *                  element it the certificate array.
     * @return true if the the certificates match, false otherwise.
     */
    private boolean checkDynamicPinning(String hostname, Certificate leafCert) {

        // Check if we have the cert for the hostname in the sdk cache
        if (ApproovAttestation.shared().getCert(hostname) == null) {
            // Do the token fetch that we must have missed previously.
            ApproovAttestation.AttestationResult result = ApproovAttestation.shared()
                    .fetchApproovTokenAndWait(hostname).getResult();
            // If the fetch failed then we give up
            if (result == ApproovAttestation.AttestationResult.FAILURE) {
                return false;
            }
        }

        // This should always work now.
        byte[] certBytes = ApproovAttestation.shared().getCert(hostname);
        if (certBytes == null) {
            return false;
        }

        // Convert bytes into cert for comparison
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certBytes));

            if (cert.equals(leafCert)) {
                return true;
            } else {
                // We need to flush the cert cache so that connections to other hosts don't fail just because this one failed the cert check
                ApproovAttestation.shared().clearCerts();
                return false;
            }

        } catch (CertificateException e) {
            // We need to flush the cert cache so that connections to other hosts don't fail just because this one failed to get a cert
            ApproovAttestation.shared().clearCerts();
            return false;
        }


    }

    @Override
    public boolean verify(String hostname, SSLSession session) {
        if (delegate.verify(hostname, session)) try {
            // Assume the leaf cert is at element 0 in the getPeerCertificates() array.
            return checkDynamicPinning(hostname, session.getPeerCertificates()[0]);
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }

        return false;
    }
}
