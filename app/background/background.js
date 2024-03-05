'use strict'

import { getDomainNameFromURL } from "../js_lib/domain.js"
import { FpkiRequest } from "../js_lib/fpki-request.js"
    import { printMap, cLog, mapGetList, mapGetMap, mapGetSet, trimString } from "../js_lib/helper.js"
import { config, downloadConfig, initializeConfig, getConfig, saveConfig, resetConfig, setConfig, exportConfigToJSON } from "../js_lib/config.js"
import { LogEntry, getLogEntryForRequest, downloadLog, printLogEntriesToConsole, getSerializedLogEntries } from "../js_lib/log.js"
import { FpkiError, errorTypes } from "../js_lib/errors.js"
import { policyValidateConnection, legacyValidateConnection, legacyValidateConnectionGo, policyValidateConnectionGo } from "../js_lib/validation.js"
import { hasApplicablePolicy, getShortErrorMessages, hasFailedValidations, LegacyTrustDecisionGo, PolicyTrustDecisionGo, getLegacyValidationErrorMessageGo, getPolicyValidationErrorMessageGo} from "../js_lib/validation-types.js"
import "../js_lib/wasm_exec.js"
import { addCertificateChainToCacheIfNecessary, getCertificateEntryByHash } from "../js_lib/cache.js"
import { VerifyAndGetMissingIDsResponseGo, AddMissingPayloadsResponseGo } from "../js_lib/FP-PKI-accessor.js"


try {
    initializeConfig();
    window.GOCACHE = getConfig("wasm-certificate-parsing");
    window.GOCACHEV2 = getConfig("wasm-certificate-caching");
} catch (e) {
    console.log("initialize: " + e);
}

// flag whether to use Go cache
// instance to call Go Webassembly functions
if (window.GOCACHE) {
    const go = new Go();
    WebAssembly.instantiateStreaming(fetch("../js_lib/wasm/parsePEMCertificates.wasm"), go.importObject).then((result) => {
        go.run(result.instance);
    });
} else if (window.GOCACHEV2) {
    try {
        const go = new Go();
        WebAssembly.instantiateStreaming(fetch("../go_wasm/gocachev2.wasm"), go.importObject).then((result) => {
            go.run(result.instance);
            const nCertificatesAdded = initializeGODatastructures("embedded/ca-certificates", "embedded/pca-certificates", exportConfigToJSON(getConfig()));
            console.log(`[Go] Initialize cache with trust roots: #certificates = ${nCertificatesAdded[0]}, #policies = ${nCertificatesAdded[1]}`);

            // make js classes for encapsulating return values available to WASM
            window.LegacyTrustDecisionGo = LegacyTrustDecisionGo;
            window.PolicyTrustDecisionGo = PolicyTrustDecisionGo;
            window.VerifyAndGetMissingIDsResponseGo = VerifyAndGetMissingIDsResponseGo;
            window.AddMissingPayloadsResponseGo = AddMissingPayloadsResponseGo;

        });
    } catch (error) {
        console.log(`failed to initiate wasm context: ${error}`);
    }
}

/** 
 * Receive one way messages from extension pages
 */
browser.runtime.onConnect.addListener( (port) => {

    port.onMessage.addListener(async (msg) => {
        switch (msg.type) {
        case "acceptCertificate":
            const {domain, certificateFingerprint, tabId, url} = msg;
            trustedCertificates.set(domain, mapGetSet(trustedCertificates, domain).add(certificateFingerprint));
            browser.tabs.update(tabId, {url: url});
            break;
        case 'postConfig':
            try {
                setConfig(msg.value);
                saveConfig();
                break;
            } catch (e) {
                console.log(e);
            }
        default:
            switch (msg) {
            case 'initFinished':
                console.log("MSG RECV: initFinished");
                port.postMessage({msgType: "config", value: config});
                break;
            case 'printConfig':
                console.log("MSG RECV: printConfig");
                port.postMessage({msgType: "config", value: config});
                break;
            case 'downloadConfig':
                console.log("MSG RECV: downloadConfig");
                downloadConfig()
                break;
            case 'resetConfig':
                exit(1);
                console.log("MSG RECV: resetConfig");
                resetConfig()
                break;
            case 'openConfigWindow':
                browser.tabs.create({url: "../htmls/config-page/config-page.html"});
                break;
            case 'showValidationResult':
                port.postMessage({msgType: "validationResults", value: trustDecisions, config});
                break;
            case 'printLog':
                printLogEntriesToConsole();
                break;
            case 'downloadLog':
                downloadLog();
                break;
            case 'getLogEntries':
                port.postMessage({msgType: "logEntries", value: getSerializedLogEntries()});
                break;
            case 'requestConfig':
                port.postMessage("Hi there");
                break;
            }
        }
    });
})

/**
 * Receive messages with possibility of direct response
 */
browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
    
    switch(request) {
        case 'requestConfig':
            return Promise.resolve({ "config": config });
        case 'resetConfig':
            resetConfig();
            saveConfig();
            return Promise.resolve({ "config": config });
        
        default:
            switch (request['type']) {
                case "uploadConfig":
                    console.log("uploading new config value...");
                    setConfig(request['value']);
                    saveConfig();
                    return Promise.resolve({ "config": config });
                default:
                    console.log(`Received unknown message: ${request}`);
                    break;
            }
    }
});


// window.addEventListener('unhandledrejection', function(event) {
//   // the event object has two special properties:
//   alert(event.promise); // [object Promise] - the promise that generated the error
//   alert(event.reason); // Error: Whoops! - the unhandled error object
// });


const trustDecisions = new Map();

// cache mapping (domain, leaf certificate fingerprint) tuples to legacy trust decisions.
const legacyTrustDecisionCache = new Map();

// cache mapping (domain, leaf certificate fingerprint) tuples to policy trust decisions.
const policyTrustDecisionCache = new Map();

// contains certificates that are trusted even if legacy (and policy) validation fails
// data structure is a map [domain] => [x509 fingerprint]
// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/CertificateInfo
const trustedCertificates = new Map();

function redirect(details, error, certificateChain=null) {
    cLog(details.requestId, "verification failed! -> redirecting. Reason: " + error+ " ["+details.url+"]");
    // if any error is caught, redirect to the blocking page, and show the error page
    let { tabId } = details;
    let htmlErrorFile;
    let reason = error.toString();
    let stacktrace = null;
    if (error.errorType === errorTypes.MAPSERVER_NETWORK_ERROR) {
        htmlErrorFile = "../htmls/map-server-error/block.html";
    } else if (error.errorType === errorTypes.LEGACY_MODE_VALIDATION_ERROR) {
        htmlErrorFile = "../htmls/validation-error-warning/block.html";
    } else if (error.errorType === errorTypes.POLICY_MODE_VALIDATION_ERROR) {
        htmlErrorFile = "../htmls/validation-error-blocking/block.html";
    } else {
        htmlErrorFile = "../htmls/other-error/block.html";
        stacktrace = error.stack;
    }

    let url = browser.runtime.getURL(htmlErrorFile) + "?reason=" + encodeURIComponent(reason) + "&domain=" + encodeURIComponent(getDomainNameFromURL(details.url));

    if (stacktrace !== null) {
        url += "&stacktrace="+encodeURIComponent(stacktrace);
    }

    // set the gobackurl such that if the user accepts the certificate of the main page, he is redirected to this same main page.
    // But if a resource such as an embedded image is blocked, the user should be redirected to the document url of the main page (and not the resource)
    if (typeof details.documentUrl === "undefined") {
        url += "&url=" + encodeURIComponent(details.url);
    } else {
        url += "&url=" + encodeURIComponent(details.documentUrl);
    }

    if (certificateChain !== null) {
        url += "&fingerprint="+encodeURIComponent(certificateChain[0].fingerprintSha256);
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
    cLog(details.requestId, "requestInfo ["+trimString(details.url)+"]");

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

async function getTlsCertificateChain(securityInfo) {
    const chain = securityInfo.certificates.map(c => ({pem: window.btoa(String.fromCharCode(...c.rawDER)), fingerprintSha256: c.fingerprint.sha256, serial: c.serialNumber, isBuiltInRoot: c.isBuiltInRoot, subject: c.subject, issuer: c.issuer}));
    // Note: the string representation of the subject and issuer as presented by the browser may differ from the string representation of the golang library. Only use this information for output and not for making decisions.
    return chain;
}

async function checkInfo(details) {
    const onHeadersReceived = performance.now();
    const logEntry = getLogEntryForRequest(details.requestId);
    cLog(details.requestId, "checkInfo ["+trimString(details.url)+"]");
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

    if (remoteInfo.certificates === undefined) {
        cLog(details.requestId, "establishing non-secure http connection");
        // TODO: could also implement protection against http downgrade
        return;
    }

    const certificateChain = await getTlsCertificateChain(remoteInfo);

    if (logEntry !== null) {
        logEntry.certificateChainReceived(certificateChain);
    }

    let decision = "accept";
    try {
        // check if this certificate for this domain was accepted despite the F-PKI legacy (or policy) warning
        const certificateFingerprint = certificateChain[0].fingerprintSha256;
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
                // cLog(details.requestId, "await fpki request for ["+domain+", "+mapserver.identity+"]");
                const {policies, certificates, metrics} = await fpkiRequest.fetchPolicies();
                policiesMap.set(mapserver, policies);
                certificatesMap.set(mapserver, certificates);
                if (logEntry !== null) {
                    logEntry.fpkiResponse(mapserver, policies, certificates, metrics);
                }
                // cLog(details.requestId, "await finished for fpki request for ["+domain+", "+mapserver.identity+"]");
            }

            // remember if policy validations has been performed
            let policyChecksPerformed = false;

            if (window.GOCACHEV2) {
                // check if have a cached trust decision for this domain+leaf certificate
                const key = domain + certificateChain[0].fingerprintSha256;
                var trustDecision = null;
                trustDecision = policyTrustDecisionCache.get(key);
                var currentTime = new Date();
                if (trustDecision === undefined || currentTime > trustDecision.validUntil) {
                    trustDecision = policyValidateConnectionGo(certificateChain, domain);
                    if (trustDecision.policyChain.length > 0) {
                        policyChecksPerformed = true;
                    }
                    policyTrustDecisionCache.set(key, trustDecision)

                }
                addTrustDecision(details, trustDecision);
                if (trustDecision.evaluationResult !== 1) {
                    throw new FpkiError(errorTypes.POLICY_MODE_VALIDATION_ERROR, getPolicyValidationErrorMessageGo(trustDecision));
                }
            } else {
                // check each policy and throw an error if one of the verifications fails
                policiesMap.forEach((p, m) => {
                    // cLog(details.requestId, "starting policy verification for ["+domain+", "+m.identity+"] with policies: "+printMap(p));

                    const { trustDecision } = policyValidateConnection(certificateChain, config, domain, p, m);
                    addTrustDecision(details, trustDecision);

                    if (hasApplicablePolicy(trustDecision)) {
                        policyChecksPerformed = true;
                    }
                    if (hasFailedValidations(trustDecision)) {
                        throw new FpkiError(errorTypes.POLICY_MODE_VALIDATION_ERROR, getShortErrorMessages(trustDecision)[0]);
                    }
                });
            }

            // don't perform legacy validation if policy validation has already taken place
            if (!policyChecksPerformed) {
                if(window.GOCACHEV2) {
                    // check if have a cached trust decision for this domain+leaf certificate
                    const key = domain+certificateChain[0].fingerprintSha256;
                    var trustDecision = null;
                    trustDecision = legacyTrustDecisionCache.get(key);
                    var currentTime = new Date();
                    if (trustDecision === undefined || currentTime > trustDecision.validUntil) {
                        trustDecision = legacyValidateConnectionGo(certificateChain, domain);
                        legacyTrustDecisionCache.set(key, trustDecision)

                    }
                    addTrustDecision(details, trustDecision);
                    if (trustDecision.evaluationResult !== 1) {
                        throw new FpkiError(errorTypes.LEGACY_MODE_VALIDATION_ERROR, getLegacyValidationErrorMessageGo(trustDecision));
                    }
                } else {
                    // check each policy and throw an error if one of the verifications fails
                    certificatesMap.forEach((c, m) => {
                        cLog(details.requestId, "starting legacy verification for ["+domain+", "+m.identity+"] with policies: "+printMap(c));
                        const {trustDecision} = legacyValidateConnection(certificateChain, config, domain, c, m);
                        addTrustDecision(details, trustDecision);
                        if (hasFailedValidations(trustDecision)) {
                            throw new FpkiError(errorTypes.LEGACY_MODE_VALIDATION_ERROR, getShortErrorMessages(trustDecision)[0]);
                        }
                    });
                }
            }

            // TODO: legacy (i.e., certificate-based) validation

            // TODO: check connection for all policies and continue if at least config.get("mapserver-quorum") responses exist

            // TODO: what happens if a response is invalid? we should definitely log it, but we could ignore it if enough other valid responses exist

            cLog(details.requestId, "verification succeeded! ["+details.url+"]");
        }
    } catch (error) {
        // TODO: in case that an exception was already thrown in requestInfo, then the redirection occurs twice (but this is not an issue since they both redirect to the same error url)
        decision = "reject: "+error
        redirect(details, error, certificateChain);
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
    cLog(details.requestId, "onCompleted ["+trimString(details.url)+"]");
    // cLog(details.requestId, printLogEntriesToConsole());
    const logEntry = getLogEntryForRequest(details.requestId);
    if (logEntry !== null) {
        cLog(details.requestId, "validation skipped (invoked onCompleted without onHeadersReceived)");
        logEntry.validationSkipped(onCompleted);
        logEntry.finalizeLogEntry(details.requestId);
    }
    if (config.get("send-log-entries-via-event") && details.type === "main_frame") {
        // uncomment to communicate log entries with puppeteer instance
        // browser.tabs.executeScript(details.tabId, { file: "../content/sendLogEntries.js" })
    }
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
