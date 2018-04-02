/**********************************************************************************************
 * Project:     Approov
 * File:        CordovaApproovHttpPlugin.m
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

#import "CordovaHttpPlugin.h"
#import "CordovaApproovHttpPlugin.h"
#import "CDVFile.h"
#import "AFHTTPSessionManager.h"
#import "AFSecurityPolicy.h"
#import <Approov/Approov.h>
#import "TextResponseSerializer.h"

/**
 * AFNetworking ServerSecurityPolicyManager class which builds AFSecurityPolicy objects on the fly
 * using the X.509 DER certificate data verified by Approov for a particular API request.
 */

@interface CriticalBlueServerSecurityPolicyManager : NSObject
- (AFSecurityPolicy*) serverSecurityPolicyForHost: (NSString*) host;
- (void) updateServerSecurityPolicyCacheForHost: (NSString*) host withCert: (NSData*) leafCertData;
- (void) clearServerSecurityPolicyCacheForHost: (NSString*) host;
- (void) clearServerSecurityPolicyCache;
@end

@implementation CriticalBlueServerSecurityPolicyManager

/* Type for (leaf cert data, server security policy) tuples */
typedef NSArray<id> SecurityPolicyCacheItem;

/* Indexes into the NSArray<id> used to implement the (leafCertData, serverSecurityPolicy) tuples in the server security
 * policy cache */
static int const LeafCertData = 0;
static int const ServerSecurityPolicy = 1;

/* Type for dictionary mapping from hostname to (leaf cert data, server security policy) tuples */
typedef NSMutableDictionary<NSString*, SecurityPolicyCacheItem*> SecurityPolicyCache;

/* Dictionary, maps hostname to tuple of leaf cert data and server security policy */
static SecurityPolicyCache* serverSecurityPolicyCache = nil;

/* A ServerSecurityPolicy that always fails */
static AFSecurityPolicy* failureServerSecurityPolicy = nil;

/* Initialize class variables */
+ (void)initialize {
    if (self == [CriticalBlueServerSecurityPolicyManager class]) {
        if (serverSecurityPolicyCache == nil) {
            serverSecurityPolicyCache = [NSMutableDictionary dictionary];
        }
        if (failureServerSecurityPolicy == nil) {
            failureServerSecurityPolicy =
                [AFSecurityPolicy policyWithPinningMode: AFSSLPinningModeCertificate withPinnedCertificates: [NSSet set]];
        }
    }
}

/* Get the cached AFSecurityPolicy for a host.
 * Returns the 'failure' server security policy if there is no cached AFSecurityPolicy for the host */
- (AFSecurityPolicy*) serverSecurityPolicyForHost: (NSString*) host {
    if (host == nil) {
        return AFSecurityPolicy.defaultPolicy;
    }
    /* Return the cached server security policy, otherwise a failure policy */
    SecurityPolicyCacheItem *serverSecurityPolicyCacheItem;
    @synchronized(serverSecurityPolicyCache) {
        serverSecurityPolicyCacheItem = serverSecurityPolicyCache[host];
    }
    if (serverSecurityPolicyCacheItem == nil) {
        return failureServerSecurityPolicy;
    }
    AFSecurityPolicy* serverSecurityPolicy = serverSecurityPolicyCacheItem[ServerSecurityPolicy];
    if (serverSecurityPolicy == nil) {
        return failureServerSecurityPolicy;
    }
    return serverSecurityPolicy;
}

/* Update the cached AFSecurityPolicy for a host with a new one based on the provided certificate */
- (void) updateServerSecurityPolicyCacheForHost: (NSString*) host withCert: (NSData*) leafCertData {
    /* First make sure leafCertData is not nil. */
    if (leafCertData == nil) {
        [self clearServerSecurityPolicyCacheForHost: host];
        return;
    }
    /* Check to see if the certificates differ */
    SecurityPolicyCacheItem* serverSecurityPolicyCacheItem;
    @synchronized(serverSecurityPolicyCache) {
        serverSecurityPolicyCacheItem = serverSecurityPolicyCache[host];
    }
    NSData* cachedLeafCertData = nil;
    if (serverSecurityPolicyCacheItem != nil)
        cachedLeafCertData = serverSecurityPolicyCacheItem[LeafCertData];
    if (![leafCertData isEqualToData: cachedLeafCertData]) {
        /* Remove the old certificate from the cache */
        [self clearServerSecurityPolicyCacheForHost: host];

        /* Build the Alamofire security policy using the Approov-verified X.509 DER certificate data and add to the cache */
        NSSet *pinSet = [NSSet setWithObject: leafCertData];
        AFSecurityPolicy* serverSecurityPolicy =
            [AFSecurityPolicy policyWithPinningMode: AFSSLPinningModeCertificate withPinnedCertificates: pinSet];
        if (serverSecurityPolicy != nil) {
            @synchronized(serverSecurityPolicyCache) {
                serverSecurityPolicyCache[host] = @[leafCertData, serverSecurityPolicy];
            }
        }
    }
}

/* Clear all cached AFSecurityPolicies */
- (void) clearServerSecurityPolicyCache {
    /* Clearing the cache will result in the 'failure' server security policy being used */
    @synchronized(serverSecurityPolicyCache) {
        [serverSecurityPolicyCache removeAllObjects];
    }
}

/* Clear the cached AFSecurityPolicy for a host */
- (void) clearServerSecurityPolicyCacheForHost: (NSString*) host {
    /* Clearing the cache entry will result in the 'failure' server security policy being used */
    /* Remove the old certificate from the cache */
    if (host != nil) {
        @synchronized(serverSecurityPolicyCache) {
            [serverSecurityPolicyCache removeObjectForKey: host];
        }
    }
}

@end /* CriticalBlueServerSecurityPolicyManager */


@interface CordovaHttpPlugin(Protected)
typedef void (^RequestFailureInterceptor)(NSURLSessionTask *task, NSError *error);
typedef void (^RequestInterceptor)(AFHTTPSessionManager *manager, NSString *urlString);

+(void)addRequestInterceptor: (RequestInterceptor)requestInterceptor;
+(void)addRequestFailureInterceptor: (RequestFailureInterceptor)requestFailureInterceptor;
@end // CordovaHttpPlugin(Protected)


// Default token value indicating "no token"
static NSString *NO_TOKEN = @"";

@implementation CordovaApproovHttpPlugin {
    // CriticalBlueServerSecurityPolicyManager for AFSecurityPolicies
    CriticalBlueServerSecurityPolicyManager *serverSecurityPolicyManager;

    // Map of protected domains to a flag that indicates whether the connection that transmits the Approov token should
    // be MITM protected. Synchronization provided by addApproovProtectedDomainForURL and isApproovProtectedURL.
    NSMutableDictionary<NSString*, NSNumber*> *protectedDomains;

    // Request interceptor for setting up Approov protection
    RequestInterceptor approovProtect;

    // Request failure interceptor for clearing server security policies if required
    RequestFailureInterceptor approovFailureHandler;
}

- (void)pluginInitialize {
    [super pluginInitialize];
    /* Configure AlamoFire for certificate pinning */
    serverSecurityPolicyManager = [[CriticalBlueServerSecurityPolicyManager alloc] init];
    CriticalBlueServerSecurityPolicyManager* __weak weakServerSecurityPolicyManager = serverSecurityPolicyManager;
    protectedDomains = [NSMutableDictionary<NSString*, NSNumber*> dictionary];
    CordovaApproovHttpPlugin* __weak weakSelf = self;
    approovProtect = ^(AFHTTPSessionManager *manager, NSString *urlString) {
        NSURL *url = [NSURL URLWithString: urlString];
        if ([weakSelf isApproovProtectedURL: url]) {
            BOOL isMITMProtected = [weakSelf isApproovMITMProtectedURL: url];
            if (!isMITMProtected) {
                // Indicate that a non-URL-specific token should be requested and no MITM protection should be set up
                url = nil;
            }
            // Fetch the Approov token, check for certificate change and update the server security policy cache.
            NSString *approovToken = [weakSelf fetchApproovTokenAndUpdateSecurityPolicyForURL: url];
            if (isMITMProtected && approovToken != NO_TOKEN) {
                // Only set up dynamic cert pinning if the URL is MITM protected and we could obtain a token
                [manager setSecurityPolicy: [weakServerSecurityPolicyManager serverSecurityPolicyForHost: [url host]]];
            }
            // Add Approov header containing the token
            [manager.requestSerializer setValue: approovToken forHTTPHeaderField: @"Approov-Token"];
        }
    };
    approovFailureHandler = ^(NSURLSessionTask *task, NSError *error) {
        /* If the Alamofire response was a failure with a 'cancelled' error type and we didn't get an iOS HTTPURLResponse,
           then assume this could be because of an issue with certificate pinning, so clear the Approov-verified
           certificates and the server security policy cache */
        if (error == nil || ([error code] == NSURLErrorCancelled && task.response == nil)) {
            [[ApproovAttestee sharedAttestee] clearCerts];
            [weakServerSecurityPolicyManager clearServerSecurityPolicyCache];
        }
    };
    [CordovaHttpPlugin addRequestInterceptor: approovProtect];
    [CordovaHttpPlugin addRequestFailureInterceptor: approovFailureHandler];
}

// Add a URL's domain to the list of protected domains
- (BOOL)addApproovProtectedDomainForURL: (NSURL*)url isMITMProtected: (BOOL)isMITMProtected error: (NSError **)initializationError {
    // Check for HTTPS here to report error early
    if ([@"HTTPS" caseInsensitiveCompare: [url scheme]] != NSOrderedSame) {
        *initializationError = [NSError errorWithDomain: @"com.criticalblue.cordova.plugin.approov.http" code: 400
            userInfo: [NSDictionary dictionaryWithObject: @"Approov protected domain's URL does not specify HTTPS protocol"
            forKey: NSLocalizedDescriptionKey]];
        return NO;
    }
    // Check that the URL specifies a domain
    NSString *domain = [url host];
    if ([domain length] == 0) {
        *initializationError = [NSError errorWithDomain: @"com.criticalblue.cordova.plugin.approov.http" code: 400
            userInfo: [NSDictionary dictionaryWithObject: @"Approov protected domain's URL does not specify domain"
                forKey: NSLocalizedDescriptionKey]];
        return NO;
    }
    @synchronized(protectedDomains) {
        // Check that MITM protection is not being downgraded
        if ([[protectedDomains objectForKey: domain] boolValue] > isMITMProtected) {
            // Downgrading the MITM protection of an Approov protected domain is not permitted
            *initializationError = [NSError errorWithDomain: @"com.criticalblue.cordova.plugin.approov.http" code: 400
                userInfo: [NSDictionary dictionaryWithObject: @"Approov protected domain's configuration invalid"
                    forKey: NSLocalizedDescriptionKey]];
            return NO;
        }
        // Update protected domains
        [protectedDomains setObject: [NSNumber numberWithBool: isMITMProtected] forKey: domain];
    }
    return YES;
}

// Check whether an URL is Approov protected
- (BOOL)isApproovProtectedURL: (NSURL*)url {
    // Approov only protects URLs whose protocol is HTTPS
    if ([@"HTTPS" caseInsensitiveCompare: [url scheme]] != NSOrderedSame) {
        return false;
    }
    // Check whether the domain should be Approov protected
    NSString *domain = [url host];
    @synchronized(protectedDomains) {
        return [protectedDomains objectForKey: domain] != nil;
    }
}

// Check whether an URL is Approov protected, including MITM protection
- (BOOL)isApproovMITMProtectedURL: (NSURL*)url {
    // Approov only protects URLs whose protocol is HTTPS
    if ([@"HTTPS" caseInsensitiveCompare: [url scheme]] != NSOrderedSame) {
        return false;
    }
    // Check whether the domain should be Approov protected and the Approov token should be protected from MITM attack
    NSString *domain = [url host];
    @synchronized(protectedDomains) {
        return [[protectedDomains objectForKey: domain] boolValue];
    }
}

// If no URL is specified (url == nil), fetch a generic Approov token.
// Otherwise fetch a domain specific token for the domain given in the URL and, if successful, update the security
// policy cache using the domain's certificate. If no certificate can be obtained (leafCertData == nil), the security
// policy for the domain is removed from the cache.
- (NSString*)fetchApproovTokenAndUpdateSecurityPolicyForURL: (NSURL*)url {
    // Set the token string to a value that signifies that no token could be obtained
    NSString *approovToken = NO_TOKEN;
    // Fetch the token for the domain we are about to access, (url == null) signifies generic token fetch
    ApproovTokenFetchData *approovData = [[ApproovAttestee sharedAttestee] fetchApproovTokenAndWait: [url absoluteString]];
    switch (approovData.result) {
        case ApproovTokenFetchResultSuccessful:
        {
            approovToken = approovData.approovToken;
            if (url != nil) {
                NSData* leafCertData = [[ApproovAttestee sharedAttestee] getCert: [url absoluteString]];
                // Update security policy cache. If (leafCertData == nil), remove any security policy for the domain.
                [serverSecurityPolicyManager updateServerSecurityPolicyCacheForHost: [url host] withCert: leafCertData];
            }
            break;
        }
        default:
          break;
    }
    return approovToken;
}

// Report success back to the plugin's JavaScript layer
- (void) reportSuccessForCommand: (CDVInvokedUrlCommand*)command {
    NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus: CDVCommandStatus_OK messageAsDictionary: dictionary];
    [self.commandDelegate sendPluginResult: pluginResult callbackId: command.callbackId];
}

// Report failure, including an error description, back to the plugin's JavaScript layer
- (void)reportError: (NSError*)error forCommand: (CDVInvokedUrlCommand*)command {
    NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
    [dictionary setObject:[NSNumber numberWithInt:-1] forKey:@"status"];
    [dictionary setObject:[error localizedDescription] forKey:@"error"];
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR messageAsDictionary: dictionary];
    [self.commandDelegate sendPluginResult: pluginResult callbackId: command.callbackId];
}

/*
 * Configure the Cordova Approov HTTP Plugin
 *
 * Sample configuration. For details about configurations and initialization, please see the plugin documentation.
 *  {
 *      "customerName": "me",
 *      "networkTimeout": 30.0,
 *      "attestationURL": "https://me.approovr.io",
 *      "failoverURL": "https://approovfo.io/token/me/index.html",
 *      "tokenPayloadValue": "A user-defined string",
 *      "protectedDomains": [
 *          {
 *              "protectedDomainURL": "https://my.domain1.com/anEndpoint",
 *              "isMITMProtectedDomain": "true"
 *          }
 *          {
 *              "protectedDomainURL": "https://my.domain2.com/anotherEndpoint",
 *              "isMITMProtectedDomain": "false"
 *          }
 *      ]
 *  }
 */
- (void)approovConfigure: (CDVInvokedUrlCommand*)command {
    NSDictionary *config = [command.arguments objectAtIndex: 0];
    ApproovConfig* approovConfig = [[ApproovAttestee sharedAttestee] createDefaultConfig];
    BOOL needsInitialization = false;
    NSString *customerName = [config objectForKey: @"customerName"];
    if (customerName != nil) {
        approovConfig.customerName = customerName;
        needsInitialization = true;
    }
    NSNumber *networkTimeout = [config objectForKey: @"networkTimeout"];
    if (networkTimeout != nil) {
        approovConfig.networkTimeout = [networkTimeout doubleValue];
        needsInitialization = true;
    }
    NSString *attestationURL = [config objectForKey: @"attestationURL"];
    if (attestationURL != nil) {
        approovConfig.attestationURL = [NSURL URLWithString: attestationURL];
        needsInitialization = true;
    }
    NSString *failoverURL = [config objectForKey: @"failoverURL"];
    if (failoverURL != nil) {
        approovConfig.failoverURL = [NSURL URLWithString: failoverURL];
        needsInitialization = true;
    }
    if (needsInitialization) {
        // Only call initialize if any of  "customerName", "networkTimeout", "attestationURL", "failoverURL" are present
        NSError *initializationError = nil;
        if (![[ApproovAttestee sharedAttestee] initialise: approovConfig error: &initializationError]) {
            // Report error
            [self reportError: initializationError forCommand: command];
            return;
        }
    }
    NSString *tokenPayloadValue = [config objectForKey: @"tokenPayloadValue"];
    if (tokenPayloadValue != nil) {
        [[ApproovAttestee sharedAttestee] setTokenPayloadValue: tokenPayloadValue];
    }
    NSArray *protectedDomains = [config objectForKey: @"protectedDomains"];
    for (NSDictionary *protectedDomain in protectedDomains) {
        NSError *initializationError = nil;
        NSString *protectedURL = [protectedDomain objectForKey: @"protectedDomainURL"];
        BOOL isMITMProtected = [[protectedDomain objectForKey: @"isMITMProtectedDomain"] boolValue];
        if (![self addApproovProtectedDomainForURL: [NSURL URLWithString: protectedURL] isMITMProtected: isMITMProtected
                error: &initializationError]) {
            // Report error
            [self reportError: initializationError forCommand: command];
            return;
        }
    }

    // Report success
    [self reportSuccessForCommand: command];
}
@end

