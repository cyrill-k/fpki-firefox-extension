'use strict'

import {getDomainNameFromURL} from "../js_lib/domain.js"
import {checkConnection} from "../js_lib/LF-PKI-accessor.js"
import {FpkiRequest} from "../js_lib/fpki-request.js"
import {printMap, cLog, mapGetList, mapGetMap, mapGetSet} from "../js_lib/helper.js"
import {config, downloadConfig, importConfigFromJSON, initializeConfig, saveConfig, resetConfig} from "../js_lib/config.js"
import {LogEntry, getLogEntryForRequest, downloadLog, printLogEntriesToConsole} from "../js_lib/log.js"
import {FpkiError, errorTypes} from "../js_lib/errors.js"
import {policyValidateConnection, legacyValidateConnection} from "../js_lib/validation.js"
import {hasApplicablePolicy, getShortErrorMessages, hasFailedValidations} from "../js_lib/validation-types.js"

try {
    initializeConfig();
} catch (e) {
    console.log("initialize: "+e);
}

// communication between browser plugin popup and this background script
browser.runtime.onConnect.addListener(function(port) {
    port.onMessage.addListener(async function(msg) {
        switch (msg.type) {
        case "acceptCertificate":
            const {domain, certificateFingerprint, tabId, url} = msg;
            trustedCertificates.set(domain, mapGetSet(trustedCertificates, domain).add(certificateFingerprint));
            browser.tabs.update(tabId, {url: url});
            break;
        case "uploadConfig":
            console.log("setting new config value...");
            importConfigFromJSON(msg.value);
            saveConfig();
            break;
        default:
            switch (msg) {
            case 'initFinished':
                port.postMessage({msgType: "config", value: config});
                break;
            case 'printConfig':
                port.postMessage({msgType: "config", value: config});
                break;
            case 'downloadConfig':
                downloadConfig()
                break;
            case 'resetConfig':
                resetConfig()
                break;
            case 'openConfigWindow':
                browser.tabs.create({url: "../htmls/config-page/config-page.html"});
                break;
            case 'showValidationResult':
                port.postMessage({msgType: "validationResults", value: trustDecisions});
                break;
            case 'printLog':
                printLogEntriesToConsole();
                break;
            case 'downloadLog':
                downloadLog();
                break;
            }
        }
    });
})

// window.addEventListener('unhandledrejection', function(event) {
//   // the event object has two special properties:
//   alert(event.promise); // [object Promise] - the promise that generated the error
//   alert(event.reason); // Error: Whoops! - the unhandled error object
// });


const trustDecisions = new Map();

// contains certificates that are trusted even if legacy (and policy) validation fails
// data structure is a map [domain] => [x509 fingerprint]
// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/CertificateInfo
const trustedCertificates = new Map();

function redirect(details, error, certificateChain=null) {
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

    let url = browser.runtime.getURL(htmlErrorFile) + "?reason=" + encodeURIComponent(error) + "&domain=" + encodeURIComponent(getDomainNameFromURL(details.url))

    // set the gobackurl such that if the user accepts the certificate of the main page, he is redirected to this same main page.
    // But if a resource such as an embedded image is blocked, the user should be redirected to the document url of the main page (and not the resource)
    if (typeof details.documentUrl === "undefined") {
        url += "&url=" + encodeURIComponent(details.url);
    } else {
        url += "&url=" + encodeURIComponent(details.documentUrl);
    }

    if (certificateChain !== null) {
        url += "&fingerprint="+encodeURIComponent(certificateChain[0].fingerprint.sha256);
    }

    browser.tabs.update(tabId, {url: url});
}

function shouldValidateDomain(domain) {
    // ignore mapserver addresses since otherwise there would be a circular dependency which could not be resolved
    return config.get("mapservers").every(({ domain: d }) => getDomainNameFromURL(d) !== domain);
}

function addTrustDecision(details, trustDecision) {
    // find document url of this request
    const url = typeof details.documentUrl === "undefined" ? details.url : details.documentUrl;
    const urlMap = mapGetMap(trustDecisions, details.tabId);
    const tiList = mapGetList(urlMap, url);
    urlMap.set(url, tiList.concat(trustDecision));
    trustDecisions.set(details.tabId, urlMap);
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
        // check if this certificate for this domain was accepted despite the F-PKI legacy (or policy) warning
        const certificateFingerprint = remoteInfo.certificates[0].fingerprint.sha256;
        if (mapGetSet(trustedCertificates, domain).has(certificateFingerprint)) {
            cLog(details.requestId, "skipping validation for domain ("+domain+") because of the trusted certificate: "+certificateFingerprint);
        } else {
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

            // remember if policy validations has been performed
            let policyChecksPerformed = false;
            // check each policy and throw an error if one of the verifications fails
            policiesMap.forEach((p, m) => {
                cLog(details.requestId, "starting policy verification for ["+domain+", "+m.identity+"] with policies: "+printMap(p));

                const {trustDecision} = policyValidateConnection(remoteInfo, config, domain, p, m);
                addTrustDecision(details, trustDecision);

                if (hasApplicablePolicy(trustDecision)) {
                    policyChecksPerformed = true;
                }
                if (hasFailedValidations(trustDecision)) {
                    throw new FpkiError(errorTypes.POLICY_MODE_VALIDATION_ERROR, getShortErrorMessages(trustDecision)[0]);
                }
            });

            // don't perform legacy validation if policy validation has already taken place
            if (!policyChecksPerformed) {
                // check each policy and throw an error if one of the verifications fails
                certificatesMap.forEach((c, m) => {
                    cLog(details.requestId, "starting legacy verification for ["+domain+", "+m.identity+"] with policies: "+printMap(c));
                    const {trustDecision} = legacyValidateConnection(remoteInfo, config, domain, c, m);
                    addTrustDecision(details, trustDecision);
                    if (hasFailedValidations(trustDecision)) {
                        throw new FpkiError(errorTypes.LEGACY_MODE_VALIDATION_ERROR, getShortErrorMessages(trustDecision)[0]);
                    }
                });
            }

            // TODO: legacy (i.e., certificate-based) validation

            // TODO: check connection for all policies and continue if at least config.get("mapserver-quorum") responses exist

            // TODO: what happens if a response is invalid? we should definitely log it, but we could ignore it if enough other valid responses exist

            cLog(details.requestId, "verification succeeded! ["+details.url+"]");
        }
    } catch (error) {
        // TODO: in case that an exception was already thrown in requestInfo, then the redirection occurs twice (but this is not an issue since they both redirect to the same error url)
        decision = "reject: "+error
        redirect(details, error, remoteInfo.certificates);
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
