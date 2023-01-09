'use strict'

import {getDomainNameFromURL} from "../js_lib/domain.js"
import {checkConnection} from "../js_lib/LF-PKI-accessor.js"
import {FpkiRequest} from "../js_lib/fpki-request.js"
import {printMap, cLog} from "../js_lib/helper.js"
import {config} from "../js_lib/config.js"
import {LogEntry, getLogEntryForRequest, downloadLog, printLogEntriesToConsole} from "../js_lib/log.js"
import {FpkiError, errorTypes} from "../js_lib/errors.js"
import {policyValidateConnection, legacyValidateConnection} from "../js_lib/validation.js"

// communication between browser plugin popup and this background script
browser.runtime.onConnect.addListener(function(port) {
    port.onMessage.addListener(function(msg) {
        switch (msg) {
        case 'printLog':
            printLogEntriesToConsole();
            break;
        case 'downloadLog':
            downloadLog();
            break;
        }
    });
})

// window.addEventListener('unhandledrejection', function(event) {
//   // the event object has two special properties:
//   alert(event.promise); // [object Promise] - the promise that generated the error
//   alert(event.reason); // Error: Whoops! - the unhandled error object
// });

// TODO: remove duplicate local mapserver (only used for testing)
// use 127.0.0.11 instead of localhost to distinguish the second test server from the first one (although it is the same instance)
// also, using 127.0.0.11 ensures that the mapserver IPs do not clash with the local test webpage at 127.0.0.1
config.set("mapservers", [
    {"identity": "local-mapserver", "domain": "http://localhost:8080", "querytype": "lfpki-http-get"},
    {"identity": "local-mapserver-2", "domain": "http://127.0.0.11:8080", "querytype": "lfpki-http-get"}
]);
// cache timeout in ms
config.set("cache-timeout", 10000);
// max amount of time in ms that a connection setup takes. Used to ensure that a cached policy that is valid at the onBeforeRequest event is still valid when the onHeadersReceived event fires.
config.set("max-connection-setup-time", 1000);
// quorum of trusted map servers necessary to accept their result
config.set("mapserver-quorum", 2);
// number of mapservers queried per validated domain (currently always choosing the first n entries in the mapserver list)
config.set("mapserver-instances-queried", 2);
config.set("ca-sets", (()=>{
    const caSet = new Map();
    caSet.set("US CA", ["CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
                        "CN=GTS Root R1,O=Google Trust Services LLC,C=US",
                        "CN=Amazon,OU=Server CA 1B,O=Amazon,C=US",
                        "CN=Amazon Root CA 1,O=Amazon,C=US",
                        "CN=DigiCert Global CA G2,O=DigiCert Inc,C=US",
                        "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US"]);
    // don't include "C=US,O=Microsoft Corporation,CN=Microsoft RSA TLS CA 02"
    caSet.set("Microsoft CA", ["CN=Microsoft RSA Root Certificate Authority 2017,O=Microsoft Corporation,C=US",
                               "CN=Microsoft ECC Root Certificate Authority 2017,O=Microsoft Corporation,C=US",
                               "CN=Microsoft RSA TLS CA 01,O=Microsoft Corporation,C=US"]);
    return caSet;
})());
// the default level of a root certificate is 0
// CAs with higher levels take precedence over CAs with lower levels
config.set("legacy-trust-preference", (()=>{
    const tp = new Map();
    tp.set("google.com", [{caSet: "US CA", level: 1}]);
    tp.set("qq.com", [{caSet: "US CA", level: 1}]);
    tp.set("azure.microsoft.com", [{caSet: "Microsoft CA", level: 1}]);
    tp.set("bing.com", [{caSet: "Microsoft CA", level: 1}]);
    return tp;
})());
// the default level of a root certificate is 0
// CAs with higher levels take precedence over CAs with lower levels
config.set("policy-trust-preference", (()=>{
    const tp = new Map();
    tp.set("*", [{pca: "pca", level: 1}]);
    return tp;
})());
config.set("root-pcas", (()=>{
    const rootPcas = new Map();
    rootPcas.set("pca", "local PCA for testing purposes");
    return rootPcas;
})());
config.set("root-cas", (()=>{
    const rootCas = new Map();
    rootCas.set("GTS CA 1C3", "description: ...");
    rootCas.set("DigiCert Global Root CA", "description: ...");
    rootCas.set("TrustAsia TLS RSA CA", "description: ...");
    rootCas.set("DigiCert SHA2 Secure Server CA", "description: ...");
    rootCas.set("DigiCert Secure Site CN CA G3", "description: ...");
    rootCas.set("GlobalSign Organization Validation CA - SHA256 - G2", "description: ...");
    rootCas.set("DigiCert TLS Hybrid ECC SHA384 2020 CA1", "description: ...");
    return rootCas;
})());

function redirect(details, error) {
    cLog(details.requestId, "verification failed! -> redirecting. Reason: " + error+ " ["+details.url+"]");
    // if any error is caught, redirect to the blocking page, and show the error page
    let { tabId } = details;
    let htmlErrorFile;
    if (error.errorType === errorTypes.MAPSERVER_NETWORK_ERROR) {
        htmlErrorFile = "../htmls/map-server-error/block.html";
    } else if (error.errorType === errorTypes.LEGACY_MODE_VALIDATION_ERROR) {
        htmlErrorFile = "../htmls/validation-error-warning/block.html";
    } else if (error.errorType === errorTypes.POLICY_MODE_VALIDATION_ERROR) {
        htmlErrorFile = "../htmls/validation-error-blocking/block.html";
    } else {
        htmlErrorFile = "../htmls/block.html";
    }
    chrome.tabs.update(tabId, {
        url: browser.runtime.getURL(htmlErrorFile) + "?reason=" + encodeURIComponent(error) + "&domain=" + encodeURIComponent(getDomainNameFromURL(details.url))
    });
}

function shouldValidateDomain(domain) {
    // ignore mapserver addresses since otherwise there would be a circular dependency which could not be resolved
    return config.get("mapservers").every(({ domain: d }) => getDomainNameFromURL(d) !== domain);
}

async function requestInfo(details) {
    const perfStart = performance.now();
    const startTimestamp = new Date();
    cLog(details.requestId, "requestInfo ["+details.url+"]");

    const domain = getDomainNameFromURL(details.url);
    if (!shouldValidateDomain(domain)) {
        // cLog(details.requestId, "ignoring (no requestInfo): " + domain);
        return;
    }
    const logEntry = new LogEntry(startTimestamp, domain, details.tabId, details.method, details.type, perfStart);
    for (const [index, mapserver] of config.get("mapservers").entries()) {
        if (index === config.get("mapserver-instances-queried")) {
            break;
        }
        // could randomize the queried mapservers and remember which were queried by keeping a global map of the form [details.requestId: Array[index]]
        const fpkiRequest = new FpkiRequest(mapserver, domain, details.requestId);

        const policiesPromise = fpkiRequest.initiateFetchingPoliciesIfNecessary();
        // the following is necessary to prevent a browser warning: Uncaught (in promise) Error: ...
        policiesPromise.catch((error) => {
            logEntry.fpkiRequestInitiateError(mapserver.identity, error.message);
            // do not redirect here for now since we want to have a single point of redirection to simplify logging
            cLog(details.requestId, "initiateFetchingPoliciesIfNecessary catch");
            redirect(details, error);
            throw error;
        });
    }
    // cLog(details.requestId, "tracking request: "+JSON.stringify(details));
    logEntry.trackRequest(details.requestId);
}

async function checkInfo(details) {
    const onHeadersReceived = performance.now();
    const logEntry = getLogEntryForRequest(details.requestId);
    cLog(details.requestId, "checkInfo ["+details.url+"]");
    const domain = getDomainNameFromURL(details.url);
    if (!shouldValidateDomain(domain)) {
        // cLog(details.requestId, "ignoring (no checkInfo): " + domain);
        return;
    }
    if (logEntry === null && details.fromCache) {
        // ensure that if checkInfo is called multiple times for a single request, logEntry is ignored
        cLog(details.requestId, "skipping log entry for cached request: "+details);
    }
    if (logEntry === null && !details.fromCache) {
        // ensure that if checkInfo is called multiple times for a single request, logEntry is ignored
        cLog(details.requestId, "no log entry for uncached request: "+details);
        throw new FpkiError(errorTypes.INTERNAL_ERROR);
    }

    const remoteInfo = await browser.webRequest.getSecurityInfo(details.requestId, {
        certificateChain: true,
        rawDER: true
    });

    cLog(details.requestId, remoteInfo);
    if (remoteInfo.certificates === undefined) {
        cLog(details.requestId, "establishing non-secure http connection");
        // TODO: could also implement protection against http downgrade
        return;
    }

    if (logEntry !== null) {
        const certificateChain = remoteInfo.certificates.map(c => ({fingerprintSha256: c.fingerprint.sha256, serial: c.serialNumber, subject: c.subject, issuer: c.issuer}));
        logEntry.certificateChainReceived(certificateChain);
    }

    let decision = "accept";
    try {
        const policiesMap = new Map();
        const certificatesMap = new Map();
        for (const [index, mapserver] of config.get("mapservers").entries()) {
            if (index === config.get("mapserver-instances-queried")) {
                break;
            }
            const fpkiRequest = new FpkiRequest(mapserver, domain, details.requestId);
            cLog(details.requestId, "await fpki request for ["+domain+", "+mapserver.identity+"]");
            const {policies, certificates, metrics} = await fpkiRequest.fetchPolicies();
            policiesMap.set(mapserver, policies);
            certificatesMap.set(mapserver, certificates);
            if (logEntry !== null) {
                logEntry.fpkiResponse(mapserver, policies, certificates, metrics);
            }
            cLog(details.requestId, "await finished for fpki request for ["+domain+", "+mapserver.identity+"]");
        }

        // count how many policy validations were performed
        var policyChecksPerformed = 0;
        // check each policy and throw an error if one of the verifications fails
        policiesMap.forEach((p, m) => {
            cLog(details.requestId, "starting policy verification for ["+domain+", "+m.identity+"] with policies: "+printMap(p));
            const {success, violations, checksPerformed} = policyValidateConnection(remoteInfo, config, domain, p);
            console.log("checks performed = "+checksPerformed);
            policyChecksPerformed += checksPerformed;
            if (!success) {
                throw new FpkiError(errorTypes.POLICY_MODE_VALIDATION_ERROR, violations[0].reason+" ["+violations[0].pca+"]");
            }
        });

        // don't perform legacy validation if policy validation has already taken place
        if (policyChecksPerformed === 0) {
            // check each policy and throw an error if one of the verifications fails
            certificatesMap.forEach((c, m) => {
                cLog(details.requestId, "starting legacy verification for ["+domain+", "+m.identity+"] with policies: "+printMap(c));
                const {success, violations} = legacyValidateConnection(remoteInfo, config, domain, c);
                if (!success) {
                    throw new FpkiError(errorTypes.LEGACY_MODE_VALIDATION_ERROR, violations[0].reason+" ["+violations[0].ca+"]");
                }
            });
        }

        // TODO: legacy (i.e., certificate-based) validation

        // TODO: check connection for all policies and continue if at least config.get("mapserver-quorum") responses exist

        // TODO: what happens if a response is invalid? we should definitely log it, but we could ignore it if enough other valid responses exist

        cLog(details.requestId, "verification succeeded! ["+details.url+"]");
    } catch (error) {
        // TODO: in case that an exception was already thrown in requestInfo, then the redirection occurs twice (but this is not an issue since they both redirect to the same error url)
        decision = "reject: "+error
        redirect(details, error);
        throw error;
    } finally {
        if (logEntry !== null) {
            const onHeadersReceivedFinished = performance.now();
            logEntry.validationFinished(decision, onHeadersReceived, onHeadersReceivedFinished);
            logEntry.finalizeLogEntry(details.requestId);
        }
    }
}

// function extractTimings(timingEntry) {
//     return {
//         dnsLookup: timingEntry.domainLookupEnd-timingEntry.domainLookupStart,
//         transportSetup: timingEntry.connectEnd - timingEntry.connectStart,
//         secureTransportSetup: timingEntry.connectEnd - timingEntry.secureConnectionStart
//     };
// }

async function onCompleted(details) {
    const onCompleted = performance.now();
    const domain = getDomainNameFromURL(details.url);
    if (!shouldValidateDomain(domain)) {
        // cLog(details.requestId, "ignoring (no requestInfo): " + domain);
        return;
    }
    cLog(details.requestId, "onCompleted ["+details.url+"]");
    // cLog(details.requestId, printLogEntriesToConsole());
    const logEntry = getLogEntryForRequest(details.requestId);
    if (logEntry !== null) {
        cLog(details.requestId, "validation skipped (invoked onCompleted without onHeadersReceived)");
        logEntry.validationSkipped(onCompleted);
        logEntry.finalizeLogEntry(details.requestId);
    }
    const remoteInfo = await browser.webRequest.getSecurityInfo(details.requestId, {
        certificateChain: true,
        rawDER: true
    });
}

// add listener to header-received.
browser.webRequest.onBeforeRequest.addListener(
    requestInfo, {
        urls: ["*://*/*"]
    },
    [])

// add listener to header-received. 
browser.webRequest.onHeadersReceived.addListener(
    checkInfo, {
        urls: ["*://*/*"]
    },
    ['blocking', 'responseHeaders'])

browser.webRequest.onCompleted.addListener(
    onCompleted, {
        urls: ["*://*/*"]
    })
