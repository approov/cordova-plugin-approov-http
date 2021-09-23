> **IMPORTANT** This repository relates to Approov 1 which is **deprecated**. For up to date information about using Approov with Cordova please refer to [Approov Quickstart: Cordova](https://github.com/approov/quickstart-cordova-advancedhttp#approov-quickstart-cordova).

Cordova Approov HTTP
====================

Cordova / Phonegap plugin that, when used alongside Cordova Advanced HTTP, adds Approov Mobile API Protection to request made through Cordova Advanced HTTP. The domains to protect are user-configurable and default to none (in which case Cordova Advanced HTTP's original behaviour is unaltered).

CriticalBlue's Approov protects mobile APIs by enabling dynamic software attestation for mobile apps. It allows your apps to uniquely authenticate themselves as the genuine, untampered software you originally published. Upon successfully passing the integrity check the app is granted a short lifetime token which can then be presented to your API with each request. This allows your server side implementation to differentiate between requests from known apps, which will contain a valid token, and requests from unknown sources, which will not.  
More detailed information about Approov and how it works is available at the [Approov web-site](https://www.approov.io).
There you can also sign up for a [free one-month trial of the Approov service](https://www.approov.io/index.html#pricing).
If you have any questions or problems then please get in touch via [Approov support](https://approov.zendesk.com).

Cordova Advanced HTTP, a popular plugin for communicating with HTTP servers, is available at Github ([https://github.com/silkimen/cordova-plugin-advanced-http](https://github.com/silkimen/cordova-plugin-advanced-http)) or NPM ([https://www.npmjs.com/package/cordova-plugin-advanced-http](https://www.npmjs.com/package/cordova-plugin-advanced-http)).


Prerequisites
-------------

* **Cordova Advanced HTTP** with CriticalBlue modifications, available at GitHub ([https://github.com/approov/cordova-plugin-advanced-http](https://github.com/approov/cordova-plugin-advanced-http)).  
  The CriticalBlue modifications are hooks that allow custom, user-defined interceptor functions to be called before requests are sent. This enables special handling and last-minute modification of requests. The modifications are not Approov specific and do not change Cordova Advanced HTTP's behaviour if the hooks are not used. In the long term we hope to get our generic modifications included in Cordova Advanced HTTP's mainline.
  
* **Approov SDK**  
  The Cordova Approov HTTP plugin contains an instance of the Approov SDK and can be used once you have signed up to Approov (free one-month trial), see below.  
  If you already are an Approov customer you can replace the Approov SDK downloaded as part of this plugin with the Approov SDK provided to you when you signed up and start using the Cordova Approov HTTP plugin right away.

* **Subscription to Approov**  
  Please [sign up to Approov](https://www.approov.io/index.html#pricing) -- a one-month trial is free. After sign-up it is important to let us know that you intend to use the Cordova Approov HTTP plugin so we can set up the service correctly. Please submit a [support request](https://approov.zendesk.com/hc/en-gb/requests/new) using "Cordova Approov HTTP Plugin" as the subject.


Usage
-----

1. Add Cordova Advanced HTTP (cordova-plugin-advanced-http) to your Cordova app

    Example:

            cordova plugin add local/path/to/cordova-plugin-advanced-http

    Ensure cordova-plugin-advanced-http with CriticalBlue modifications is picked up by Cordova, *not* the cordova-plugin-advanced-http on Github, NPM or a similar source.

2. Add Approov SDK to Cordova Approov HTTP (cordova-plugin-approov-http)
    * Create a local copy of cordova-plugin-approov-http
    * Copy approov.aar and Approov.framework from your Approov SDK into the `lib` folder of the local cordova-plugin-approov-http

3. Add cordova-plugin-approov-http to your Cordova app

    Example:

            cordova plugin add local/path/to/cordova-plugin-approov-http

    Ensure that your local copy of cordova-plugin-approov-http, the one containing the Approov SDK is picked up, *not* the one on NPM.

4. Add a call to the Approov plugin's configuration function to your Cordova app. If this call is omitted, the functionality of the cordova-plugin-advanced-http with CriticalBlue modifications is identical to that of the original cordova-plugin-advanced-http.

    Configuration typically involves calling the configuration function of the Approov plugin, passing as arguments your unique customer ID (required, you received this when you signed up to the Approov trial), the token payload (optional, more below), and the URLs for the domains that should be protected and whether requests to the domains should be protected against Man-In-The-Middle (MITM) attacks (token theft).

    Example:

            var config = {
                    "customerName": "me",
                    "tokenPayloadValue": "",
                    "protectedDomains": [
                    {
                        "protectedDomainURL": "https://my.domain1.com/",
                        "isMITMProtectedDomain": "true"
                    },
                    {
                        "protectedDomainURL": "https://my.domain2.com/",
                        "isMITMProtectedDomain": "true"
                    }
                ]
            };
            cordova.plugin.approov.http.approovConfigure(
                config,
                function(response) {
                    // Success
                    console.log("Successfully set Approov protected domains");
                },
                function(response) {
                    // Failure
                    console.log("Error setting Approov protected domains: " + response.error);
                });

5. Your app probably already re-tries failed requests, but if it does not, this should be added for requests to Approov protected domains for which MITM protection (to prevent stealing of Approov tokens) has been enabled.
Requests to such domains may be cancelled because a certificate change on the connection causes the TLS handshake to fail. Certificates can change, for example, because the domain's certificate is being updated as part of routine certificate rotation, or because a MITM attack is started or terminated. Requests cancelled due to certificate change should be re-tried to trigger an update of Approov's dynamic certificate pinning with the new certificate. This will allow the app to resume normal operation after an MITM-attack ends or after a benign domain certificate change.

6. The rest is automatic. No code changes need to be made to the existing calls to the HTTP request functions, such as `get`, `put`, etc., provided by Cordova Advanced HTTP.

    Example:

            cordova.plugin.http.get("https://my.domain1.com/endpoint", {}, {}, 
                function(response) {
                    // Success
                    console.log("Get request succeeded. Status: " + response.status + ", Data: " + JSON.stringify(response.data));
                },
                function(response) {
                    // Failure
                    console.log("Get request failed. Status: " + response.status + ", Error: " + response.error);
                });



Approov Configuration Details
--------------------------------------------

This shows all available configuration parameters with example values:

        {
            "customerName": "me",
            "networkTimeout": 30.0,
            "attestationURL": "https://approov.attestation.service/",
            "failoverURL": "https://approov.failover.service/path/index.html",
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

Some of the the configuration parameters, namely `customerName`, `networkTimeout`, `attestationURL` and `failoverURL`, can only be set in the very first call to `approovConfigure` and are then immutable. If not set, they default to built-in values. Setting of any of the other parameters (`protectedDomains` and `tokenPayloadValue`) can be deferred to additional, subsequent calls to the Approov configuration function. This allows to update the token payload value or to add further protected domains later. It is optional to set them, but of course, if the token payload value is not set no associated information will be included in the token, or if no domains are added, none will be protected.

### `customerName`, `networkTimeout`, `attestationURL` and `failoverURL`

The configuration parameters `customerName`, `networkTimeout`, `attestationURL` and `failoverURL` can only be set once and must be set before the first request to any Approov protected domain is made. Apart from the customer name it is generally not necessary to set these, as the default configuration of the Appproov SDK should be suitable for all but very specialist cases.

* **customerName:** String defining the customer name  
  For configuration of Approov with a specific customer name, but otherwise using default values (mutually exclusive with attestationURL and failoverURL)
* **networkTimeout:** Number defining the network timeout in seconds  
  The network timeout used by the Approov SDK for any remote request
* **attestationURL:** String defining a valid URL  
  Overrides the Approov service URL (mutually exclusive with customerName)
* **failoverURL:** String defining a valid URL  
  Overrides the Approov failover service URL (mutually exclusive with customerName)

Example: Configuring the Approov plugin on app-start using a specific customer name:

        var config = {"customerName": "me"};
        cordova.plugin.approov.http.approovConfigure(config, successCallback, failureCallback))

### `tokenPayloadValue`

The token payload value can be changed at any time and its new value will be used in any subsequent request to Approov-protected domains. The payload is an arbitrary, ASCII encoded string for which a hash is included in the Approov token. This is intended to be used for long-lived data, such as an OAuth token or a session ID, that can be used to uniquely identify a user. Changing the value will cause a new token to be fetched from the Approov cloud service for use in the next request to an Approov-protected domain, rather than using a cached token. As such it is recommended that this value should not be changed often. If this feature is to be used, the token payload value should be set in the very first call to `approovConfigure` to ensure that a value is always available. If no suitable value is available at startup, a sentinel value that represents "invalid", such as the empty string, should be used initially.

* **tokenPayloadValue** String specifying the user-defined token payload value as an ASCII encoded string
  (see Approov SDK User Guide: Including a custom claim for [Android](https://www.approov.io/docs/androidclientapiuserguide.html#including-a-custom-claim) or [iOS](https://www.approov.io/docs/iosframeworkreference.html#including-a-custom-claim))

Example:

1. Configuring the Approov plugin on app-start using the default configuration and providing an initial (empty) token payload value:

        var config = {"tokenPayloadValue": ""};
        cordova.plugin.approov.http.approovConfigure(config, successCallback, failureCallback))

2. Updating the token payload value to contain a session ID once a user session has been established:

        var config = {"tokenPayloadValue": sessionID};
        cordova.plugin.approov.http.approovConfigure(config, successCallback, failureCallback))

### `protectedDomains`

Domains to be protected can be added by calling `approovConfigure` at any time and will automatically be protected by Approov, starting with the next request to the specified domain(s). Protection against Man-In-The-Middle (MITM) attacks (token theft) can optionally be disabled to help with debugging or if MITM-protection through certificate pinning cannot be used because the leaf certificate is not constant accross the API endpoints. It is strongly recommended to enable MITM-protection in a production setting.  
MITM protection can be enabled for an already protected domain that had MITM protection disabled when it was added initially. Removing domains from Approov protection or removing MITM-protection for a domain, once enabled, is not supported as this might pose a security risk.

* **protectedDomains:** Array of domains to be protected by Approov.  
  Any future request going out to these domains will be automatically protected by Approov.
    * **protectedDomainURL:** String specifying the URL for the domain to protect. The URL's protocol must be HTTPS and the URL must specify a domain. Any path or arguments after the domain are ignored.
    * **isMITMProtectedDomain:** Boolean ("true" or "false") specifying whether the Approov token should be protected from theft through MITM attack on the connection to the user's API. It is strongly recommended to enable this in production systems.

Example:

1. Configuring the Approov plugin on app-start using the default configuration:

        var config = {};
        cordova.plugin.approov.http.approovConfigure(config, successCallback, failureCallback))

2. Adding a protected domain (initially without MITM-protection, e.g. because we are still debugging):

        var config = {"protectedDomains": [{"protectedDomainURL": "https://my.domain1.com/anEndpoint",
                "isMITMProtectedDomain": "false"}]};
        cordova.plugin.approov.http.approovConfigure(config, successCallback, failureCallback))

3. Enable MITM-protection for previously protected domain

        var config = {"protectedDomains": [{"protectedDomainURL": "https://my.domain1.com/anEndpoint",
                "isMITMProtectedDomain": "true"}]};
        cordova.plugin.approov.http.approovConfigure(config, successCallback, failureCallback))


