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
import com.criticalblue.attestationlibrary.ApproovConfig;
import com.criticalblue.cordova.approov.http.CordovaApproovHttpUtil;

import com.synconset.cordovahttp.CordovaHttpPlugin;

import java.net.MalformedURLException;
import java.net.URL;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Cordova / Phonegap plugin that adds Approov API protection to the cordova-plugin-advanced-http HTTP plugin
 */
 public class CordovaApproovHttpPlugin extends CordovaPlugin {

    // Tag for logging
    private static final String TAG = "CordovaApproovHttpPlugin";

    // Flag indicating whether the Approov library has been initialized. This can only be done once in Android.
    private static boolean isApproovInitialized = false;

    // Determine whether the Approov library has been initialized
    private static synchronized boolean isApproovInitialized() {
        return isApproovInitialized;
    }

    // Set the flag that indicates whether the Approov library has been initialized
    private static synchronized void setApproovInitialized() {
        isApproovInitialized = true;
    }

    // Ensure the Approov library has been initialized
    private static void ensureApproovInitialized(ApproovConfig approovConfig)
            throws IllegalArgumentException, MalformedURLException {
        if (!isApproovInitialized()) {
            // Initialize Approov
            ApproovAttestation.initialize(approovConfig);
            setApproovInitialized();
        }
    }

    // Initialize plugin
    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        CordovaHttpPlugin.addRequestInterceptor(CordovaApproovHttpUtil.approovProtect);
    }

    // Execute commands from JavaScript
    /* Sample configuration. For details about configurations and initialization, please see the plugin documentation.
        {
            "customerName": "me",
            "networkTimeout": 30.0,
            "attestationURL": "https://me.approovr.io",
            "failoverURL": "https://approovfo.io/token/me/index.html",
            "tokenPayloadValue": "A user-defined string",
            "protectedDomains": [
                {
                    "protectedDomainURL": "https://my.domain1.com/anEndpoint",
                    "isMITMProtectedDomain": "true"
                }
                {
                    "protectedDomainURL": "https://my.domain2.com/anotherEndpoint",
                    "isMITMProtectedDomain": "false"
                }
            ]
        }
    */
    @Override
    public boolean execute(String action, final JSONArray args, final CallbackContext callbackContext)
            throws JSONException {
        if (action.equals("approovConfigure")) {
            // Initialize Approov using the provided configuration
            try {
                JSONObject config = args.getJSONObject(0);
                ApproovConfig approovConfig =
                    ApproovConfig.getDefaultConfig(this.cordova.getActivity().getApplicationContext());
                // Flag indicating whether ApproovAttestation.initialize() needs to be called. This is required for
                // configuration items that are managed by the Approov library, as opposed to managed by the plugin.
                boolean needsInitialization = false;
                if (config.has("customerName")) {
                    approovConfig.setCustomerName(config.getString("customerName"));
                    needsInitialization = true;
                }
                if (config.has("networkTimeout")) {
                    approovConfig.setNetworkTimeout(config.getInt("networkTimeout"));
                    needsInitialization = true;
                }
                if (config.has("attestationURL")) {
                    approovConfig.setAttestationURL(new URL(config.getString("attestationURL")));
                    needsInitialization = true;
                }
                if (config.has("failoverURL")) {
                    approovConfig.setFailoverURL(new URL(config.getString("failoverURL")));
                    needsInitialization = true;
                }
                if (needsInitialization) {
                    if (isApproovInitialized()) {
                        callbackContext.error("Approov library initialization must only be performed once for "
                            + "\"customerName\", \"networkTimeout\", \"attestationURL\" and \"failoverURL\"");
                    }
                    else {
                        ApproovAttestation.initialize(approovConfig);
                        setApproovInitialized();
                    }
                }
                if (config.has("tokenPayloadValue")) {
                    ensureApproovInitialized(approovConfig);
                    ApproovAttestation.shared().setTokenPayloadValue(config.getString("tokenPayloadValue"));
                }
                if (config.has("protectedDomains")) {
                    ensureApproovInitialized(approovConfig);
                    JSONArray protectedDomains = config.getJSONArray("protectedDomains");
                    for (int i = 0; i < protectedDomains.length() ; i += 1) {
                        JSONObject protectedDomain = protectedDomains.getJSONObject(i);
                        String protectedURL = protectedDomain.getString("protectedDomainURL");
                        boolean isMITMProtected = protectedDomain.getBoolean("isMITMProtectedDomain");
                        CordovaApproovHttpUtil.addApproovProtectedDomain(new URL(protectedURL), isMITMProtected);
                    }
                }
                callbackContext.success();
            } catch (JSONException e) {
                callbackContext.error("Error (invalid JSON) initializing Approov: " + e.getMessage());
            } catch (MalformedURLException e) {
                callbackContext.error("Error (malformed URL) initializing Approov: " + e.getMessage());
            } catch (IllegalArgumentException e) {
                callbackContext.error("Error initializing Approov: " + e.getMessage());
            } catch (Exception e) {
                callbackContext.error("Error initializing Approov: " + e.getMessage());
            }
        } else {
            return false;
        }
        return true;
    }

}
