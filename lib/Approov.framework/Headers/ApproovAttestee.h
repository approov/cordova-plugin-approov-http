/*****************************************************************************
 * Project:     Approov
 * File:        ApproovAttestee.h
 * Original:    Created on 25 April 2016 by Simon Rigg
 * Copyright(c) 2002 - 2016 by CriticalBlue Ltd.
 *
 * The "Attestee" performs the actual client app attestations via the Approov
 * cloud service in order to access a remote "Attester" and retrieve a time-
 * limited Approov token.
 ****************************************************************************/

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>


/* Forward declaration of ApproovConfig */
@class ApproovConfig;
/* Forward declaration of ApproovTokenFetchData */
@class ApproovTokenFetchData;


/**
 * This ApproovAttestee public class interface.
 */
__attribute__((visibility("default"))) @interface ApproovAttestee : NSObject

/* Enumeration of Approov token fetch results in the fetchApproovToken() callback parameters */
typedef NS_ENUM(NSUInteger, ApproovTokenFetchResult)
{
    ApproovTokenFetchResultSuccessful,
    ApproovTokenFetchResultFailed
};

/* FetchApproovTokenCompletionHandler type definition */
typedef void (^FetchApproovTokenCompletionHandler)(ApproovTokenFetchResult result, NSString* _Nonnull approovToken) DEPRECATED_MSG_ATTRIBUTE("Use FetchApproovTokenCompletionHandler2");

/* FetchApproovTokenCompletionHandler2 type definition */
typedef void (^FetchApproovTokenCompletionHandler2)(ApproovTokenFetchData * _Nonnull data);

/**
 * Get the singleton shared ApproovAttestee instance.
 *
 * @result the singleton shared ApproovAttestee instance
 */
+ (_Nullable instancetype)sharedAttestee;

/**
 * WARNING: Do not create individual instances of this class. Instead, use ApproovAttestee.sharedAttestee to access the singleton shared
 *          instance.
 */
- (_Nullable instancetype)init NS_UNAVAILABLE;

/**
 * Create an ApproovConfig object from the default configuraton of the ApproovAttestee.
 * This is a copy of the configuraton, which you are free to modify and then use in the initialise() method.
 */
- (ApproovConfig * _Nonnull)createDefaultConfig;

/**
 * Initialise the Approov framework using the properties specified in the given config object.
 *
 * WARNING: This method must be called prior to calling fetchApproovToken() or fetchApproovTokenAndWait().
 *
 * @param config the Approov framework configuration object
 * @param error the reference to an error object which will be set if an error occurred initialising the Approov framework
 * @result true/YES if the Approov framework was successfully initialised, false/NO otherwise
 */
- (BOOL)initialise:(ApproovConfig * _Nonnull)config error:(NSError * _Null_unspecified * _Nonnull)error;

/* The current Approov token which is automatically updated when an attestation operation is performed with the Approov cloud service.
 * This result should not be cached as the value may change since Approov tokens have a limited valid lifetime. Instead, the
 * fetchApproovToken() method's callback should be observed and the Approov token retreived from the callback's approovToken parameter.
 * This property is provided simply as a convenience and for JSContext integration.
 */
@property (readonly, copy, nonnull) NSString *approovToken;

/**
 * Define an arbitrary string which will be hashed for anonymity (using a base64-encoded SHA-256 hash) and added to the
 * Approov Token as a 'PAY' custom payload claim.
 *
 * @param value the payload value to hash and include in the 'PAY' claim of an Approov token
 */
- (void)setTokenPayloadValue:(NSString * _Nonnull)value;

/** This method is deprecated and will be removed in the next Approov release */
- (void)fetchApproovToken:(FetchApproovTokenCompletionHandler _Nonnull)completionHandler DEPRECATED_MSG_ATTRIBUTE("Use the fetchApproovToken variant with URL specifier");

/**
 * Initiates an asynchronous request to perform an attestation of the running app and fetch an Approov token from the Approov cloud service.
 *
 * When the asynchronous fetch token operation is complete, the provided callback is invoked. The callback parameter is an object which contains:
 *
 *    1. An "ApproovTokenFetchResult" with fetch result indicated by "ApproovTokenFetchResult" enum in this interface
 *    2. An "ApproovToken" with NSString value corresponding to the fetched Approov token
 *
 * WARNING: The Approov token is valid for a limited time only depending on your Approov cloud service configuration and should therefore
 *          not be cached for extended periods of time. It is important to invoke fetchApproovToken() when you require a token for delivery
 *          to your web services for app authentication and this method has been optimised for frequent use.
 *
 * @param completionHandler the completion handler callback which will be called with the Approov token fetch result
 * @param url the RFC 2396 URL of the connection to be protected by Approov (only https is supported)
 */
- (void)fetchApproovToken:(FetchApproovTokenCompletionHandler2 _Nonnull)completionHandler :(NSString * _Nullable)url;

/** This method is deprecated and will be removed in the next Approov release */
- (ApproovTokenFetchData * _Nonnull)fetchApproovTokenAndWait DEPRECATED_MSG_ATTRIBUTE("Use the fetchApproovTokenAndWait variant with URL specifier");

/**
 * Initiates a synchronous request to perform an attestation of the running app and fetch an Approov token from the Approov cloud service.
 *
 * WARNING: This method blocks the caller until completion or timeout. Since fetching Approov tokens requires contacting the
 *          Approov cloud service over the WiFi or cellular network, this method may take up to several seconds to return in
 *          the worst case. Therefore this method should NOT be called in the main (UI) thread which would cause the app to
 *          appear unresponsive. In general, the preferred approach on iOS is to use asynchronous callback operations
 *          (provided by the fetchApproovToken() method). The fetchApproovTokenAndWait() method is provided only as a
 *          convenience for legacy code.
 *
 * When the synchronous fetch token operation is complete, the result and Approov token is
 * returned and the caller is unblocked. The return value object contains:
 *
 *    1. An "ApproovTokenFetchResult" with fetch result indicated by "ApproovTokenFetchResult" enum in this interface
 *    2. An "ApproovToken" with NSString value corresponding to the fetched Approov token
 *
 * WARNING: The Approov token is valid for a limited time only depending on your Approov cloud service configuration and should therefore
 *          not be cached for extended periods of time. It is important to invoke fetchApproovToken() when you require a token for delivery
 *          to your web services for app authentication and this method has been optimised for frequent use.
 *
 * @param url the RFC 2396 URL of the connection to be protected by Approov (only https is supported)
 * @result the Approov token fetch result
 */
- (ApproovTokenFetchData * _Nonnull)fetchApproovTokenAndWait:(NSString * _Nullable)url;

/**
 * Retrieve DER binary format data of the X.509 TLS leaf certificate for the given URL retrieved by Approov.
 *
 * @param url the RFC 2396 URL of the connection protected by Approov
 * @result the certificate data, or nil if the connection to the given URL has not been retrieved by Approov
 *
 * WARNING: The fetchApproovToken (or fetchApproovTokenAndWait variant) method should be invoked with the URL prior to invoking this method
 *          (or after invoking the clearCerts method) and a 'success' result must be obtained from the token fetch request.
 */
- (NSData * _Nullable)getCert:(NSString * _Nonnull)url;

/**
 * Clear the internal cache of X.509 TLS leaf certificates retrieved by Approov.
 */
- (void)clearCerts;

/**
 * Register the given UIWebView with Approov to provide Javascript interaction services.
 * When finished, it is important to call unregisterUIWebView() with the UIWebView instance.
 *
 * Currently, the only supported Javascript interface is for manually fetching Approov tokens.
 * This can be achieved by invoking the following function from Javascript in the UIWebView's main frame:
 *
 *     approov.fetchApproovToken("mySuccessCallback", "myFailureCallback");
 *
 * This will asynchronously perform an attestation of the running app and fetch an Approov token from the Approov cloud service.
 * When complete, the success or failure Javascript callback function will be invoked from the Approov framework as appropriate.
 * The success callback function should accept a single parameter: the Approov token string.
 *
 * WARNING: The Approov token is valid for a limited time only depending on your Approov cloud service configuration and should therefore
 *          not be cached for extended periods of time. It is important to invoke fetchApproovToken() when you require a token for delivery
 *          to your web services for app authentication and this method has been optimised for frequent use.
 *
 * @param webView the UIWebView instance to register
 * @result true/YES if the UIWebView was successfully registered, false/NO otherwise
 */
- (BOOL)registerUIWebView:(UIWebView * _Nonnull)webView;

/**
 * Unregister the given UIWebView with Approov.
 * This method has no effect for an unregistered UIWebView.
 *
 * @param webView the UIWebView instance to unregister
 */
- (void)unregisterUIWebView:(UIWebView * _Nonnull)webView;

/**
 * Register the given WKWebView with Approov to provide Javascript interaction services.
 * When finished, it is important to call unregisterWKWebView() with the WKWebView instance.
 *
 * Currently, the only supported Javascript interface is for manually fetching Approov tokens.
 * This can be achieved by invoking the following function from Javascript in the WKWebView's main frame:
 *
 *     approov.fetchApproovToken("mySuccessCallback", "myFailureCallback");
 *
 * This will asynchronously perform an attestation of the running app and fetch an Approov token from the Approov cloud service.
 * When complete, the success or failure Javascript callback function will be invoked from the Approov framework as appropriate.
 * The success callback function should accept a single parameter: the Approov token string.
 *
 * WARNING: The Approov token is valid for a limited time only depending on your Approov cloud service configuration and should therefore
 *          not be cached for extended periods of time. It is important to invoke fetchApproovToken() when you require a token for delivery
 *          to your web services for app authentication and this method has been optimised for frequent use.
 *
 * @param webView the WKWebView instance to register
 * @result true/YES if the WKWebView was successfully registered, false/NO otherwise
 */
- (BOOL)registerWKWebView:(WKWebView * _Nonnull)webView;

/**
 * Unregister the given WKWebView with Approov.
 * This method has no effect for an unregistered WKWebView.
 *
 * @param webView the WKWebView instance to unregister
 */
- (void)unregisterWKWebView:(WKWebView * _Nonnull)webView;

@end


/**
 * This interface is used to specify configuration properties when initialising the Approov framework.
 */
__attribute__((visibility("default"))) @interface ApproovConfig : NSObject

/* The customer unique identifier */
@property (nullable) NSString *customerName;

/* The primary URL for communication between the framework and the Approov servers */
@property (nullable) NSURL *attestationURL;

/* The backup failover URL for communication between the framework and the Approov servers */
@property (nullable) NSURL *failoverURL;

/* The timeout, in seconds, for Approov framework network communications */
@property NSTimeInterval networkTimeout;

@end


/**
 * This interface is used for the return value of the synchronous fetch Approov token method.
 */
__attribute__((visibility("default"))) @interface ApproovTokenFetchData : NSObject

/* The result of fetching an Approov token */
@property (readonly) ApproovTokenFetchResult result;

/* The Approov token (should not be cached for extended periods of time) */
@property (readonly, nonnull) NSString *approovToken;

@end
