/**********************************************************************************************
 * Project:     Approov
 * File:        CordovaApproovHttpUtil.java
 * Original:    Created on 17 Jan 2018 by johanness
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
import com.criticalblue.attestationlibrary.TokenInterface;
import com.criticalblue.cordova.approov.http.CordovaApproovHttpPinningVerifier;

import com.github.kevinsawicki.http.HttpRequest;
import com.github.kevinsawicki.http.HttpRequest.HttpRequestException;

import com.synconset.cordovahttp.CordovaHttpPlugin;

import java.io.IOException;

import java.net.HttpURLConnection;
import java.net.URL;

import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;


public final class CordovaApproovHttpUtil {

    // Tag for logging
    private static final String TAG = "CordovaApproovHttpUtil";
    
    // Default token value indicating "no token"
    private static final String NO_TOKEN = "";
    
    // Map of protected domains to a flag that indicates whether the connection that transmits the Approov token should
    // be MITM protected. Synchronization provided by addApproovProtectedDomain() and isApproovProtected()
    private static Map<String, Boolean> protectedDomains = new HashMap<String, Boolean>();

    // Add a domain to the list of protected domains. The domain is extracted from the URL argument. The URL's protocol
    // must be HTTPS.
    public static synchronized void addApproovProtectedDomain(URL url, boolean isMITMProtected) {
        // Check for HTTPS here to report error early
        if (!"https".equals(url.getProtocol())) {
            throw new IllegalArgumentException("Approov protected domain's URL does not specify HTTPS protocol");
        }
        // Check that the URL specifies a domain
        String domain = url.getHost();
        if (domain == null || domain.isEmpty()) {
            throw new IllegalArgumentException("Approov protected domain's URL does not specify domain");
        }
        // Check that MITM protection is not being downgraded
        if (protectedDomains.get(url.getHost()) != null && protectedDomains.get(url.getHost()) && !isMITMProtected) {
            // Downgrading the MITM protection of an Approov protected domain is not permitted
            throw new IllegalArgumentException("Approov protected domain's configuration invalid");
        }
        // Update protected domains
        protectedDomains.put(url.getHost(), isMITMProtected);
    }

    // Check whether an URL is Approov protected
    public static synchronized boolean isApproovProtected(URL url) {
        // Approov only protects URLs whose protocol is HTTPS
        if (!"https".equals(url.getProtocol())) {
            return false;
        }
        // Check that the domain is protected
        String domain = url.getHost();
        return protectedDomains.containsKey(domain);
    }

    // Check whether an URL is Approov protected, including MITM protection
    public static synchronized boolean isApproovMITMProtected(URL url) {
        // Approov only protects URLs whose protocol is HTTPS
        if (!"https".equals(url.getProtocol())) {
            return false;
        }
        // Check whether the domain should be Approov protected and the Approov token should be protected from MITM attack
        String domain = url.getHost();
        Boolean isMITMProtected = protectedDomains.get(domain);
        return isMITMProtected != null && isMITMProtected.booleanValue();
    }

    // If no URL is specified (url == null), fetch a generic Approov token, otherwise fetch a domain specific token for
    // the domain given in the URL.
    public static String fetchApproovToken(URL url) {
        // Set the token string to a value that signifies that no token could be obtained
        String approovToken = NO_TOKEN;

        // Fetch the token, (urlString == null) signifies generic token fetch
        String urlString = (url == null) ? null : url.toString();
        TokenInterface.ApproovResults approovAttestation = ApproovAttestation.shared().fetchApproovTokenAndWait(urlString);
        if (approovAttestation.getResult() == ApproovAttestation.AttestationResult.SUCCESS) {
            // If the fetch succeeded then we set the token string to the obtained token value
            approovToken = approovAttestation.getToken();
        }
        return approovToken;
    }

    // Set up Approov certificate pinning
    public static void setupApproovCertPinning(HttpRequest request) throws HttpRequestException {
        // Set the hostname verifier on the connection (must be HTTPS)
        final HttpURLConnection connection = request.getConnection();
        if (!(connection instanceof HttpsURLConnection))
        {
            IOException e = new IOException("Approov protected connection must be HTTPS");
            throw new HttpRequestException(e);
        }
        final HttpsURLConnection httpsConnection = ((HttpsURLConnection) connection);

        HostnameVerifier currentVerifier = httpsConnection.getHostnameVerifier();
        if (currentVerifier instanceof CordovaApproovHttpPinningVerifier)
        {
            IOException e = new IOException("There can only be one Approov certificate pinner for a connection");
            throw new HttpRequestException(e);
        }
        // Create a hostname verifier that uses Approov's dynamic pinning approach and set it on the connection
        CordovaApproovHttpPinningVerifier verifier = new CordovaApproovHttpPinningVerifier(currentVerifier);
        httpsConnection.setHostnameVerifier(verifier);
    }

    // Consumer (operates via side-effects) that sets up Approov protection for a request
    public static CordovaHttpPlugin.IHttpRequestInterceptor approovProtect =
        new CordovaHttpPlugin.IHttpRequestInterceptor() {
            @Override
            public void accept(HttpRequest request) {
                URL url = request.url();
                if (isApproovProtected(url)) {
                    final boolean isMITMProtected = isApproovMITMProtected(url);
                    if (!isMITMProtected) {
                        // Indicate that a non-URL-specific token should be requested and no MITM protection should be set up
                        url = null;
                    }
                    // Fetch the Approov token
                    String approovToken = fetchApproovToken(url);
                    if (isMITMProtected && approovToken != NO_TOKEN) {
                        // Only set up dynamic cert pinning if the request is MITM protected and we could obtain a token
                        setupApproovCertPinning(request);
                    }
                    // Add Approov header containing the token to the request
                    request.header("Approov-Token", approovToken);
                }
            }
        };

};
