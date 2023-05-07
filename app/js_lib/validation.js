import * as domainFunc from "./domain.js"
import {FpkiError} from "./errors.js"
import {printMap} from "./helper.js"
import {LegacyTrustInfo, LegacyTrustDecision, PolicyEvaluation, PolicyTrustInfo, PolicyTrustDecision, PolicyAttributes, EvaluationResult} from "./validation-types.js"
import {getSubject} from "./x509utils.js"

// policy mode
// start from highest ancestor -> go to actual domain
// for each domain in all ancestor domains (+ the actual domain), find policies issued by PCAs with highest trust level and validate the connection certificate using them
// -> behavior may change if we allow attributes to be inherited

// legacy mode
// only consider the actual domain without including ancestor domains
// including ancestor domains is difficult, because of what would happen if an ancestor cert is issued by more highly trusted CA? -> we probably cannot block the certificate as it would lead to many false positives

function policyFilterHighestTrustLevelPolicies(trustPreferenceEntries, domainPolicies) {
    let highestTrustLevelPolicies = new Map();
    let highestTrustLevel = 0;
    domainPolicies.forEach((pcaPolicy, pcaIdentifier) => {
        trustPreferenceEntries.forEach(tps => {
            tps.forEach(tp => {
                if (tp.pca === pcaIdentifier) {
                    if (tp.level > highestTrustLevel) {
                        highestTrustLevelPolicies = new Map();
                        highestTrustLevel = tp.level;
                    }
                    if (tp.level >= highestTrustLevel && !highestTrustLevelPolicies.has(pcaIdentifier)) {
                        highestTrustLevelPolicies.set(pcaIdentifier, {pcaPolicy, originTrustPreference: tp});
                    }
                }
            });
        });
    });
    return {highestTrustLevel, highestTrustLevelPolicies};
}

function policyValidateActualDomain(remoteInfo, config, actualDomain, domainPolicies) {
    const caSets = config.get("ca-sets");

    const filteredTrustPreferenceEntries = filterTrustPreferenceEntries(config.get("policy-trust-preference"), actualDomain);
    
    // get policies whose PCAs have the highest trust level (II)
    const {highestTrustLevel, highestTrustLevelPolicies} = policyFilterHighestTrustLevelPolicies(filteredTrustPreferenceEntries, domainPolicies);

    const trustInfos = [];
    highestTrustLevelPolicies.forEach(({pcaPolicy, originTrustPreference}, pcaIdentifier) => {
        if (pcaPolicy.TrustedCA !== null) {
            remoteInfo.certificates.forEach((certificate, i) => {
                // if certificate is in browsers trust store
                if (certificate.isBuiltInRoot) {
                    // check if CA is in the trusted list
                    let evaluation;
                    if (pcaPolicy.TrustedCA.every(ca => !caSets.get(ca).includes(certificate.subject))) {
                        evaluation = new PolicyEvaluation(actualDomain, PolicyAttributes.TRUSTED_CA, EvaluationResult.FAILURE, highestTrustLevel, originTrustPreference);
                    } else {
                        evaluation = new PolicyEvaluation(actualDomain, PolicyAttributes.TRUSTED_CA, EvaluationResult.SUCCESS, highestTrustLevel, originTrustPreference);
                    }
                    const trustInfo = new PolicyTrustInfo(pcaIdentifier, actualDomain, pcaPolicy, [evaluation]);
                    trustInfos.push(trustInfo);
                }
            });
        }
    });
    return {trustInfos};
}

function policyValidateParentDomain(remoteInfo, config, actualDomain, parentDomain, domainPolicies) {
    // only consider trust preference entries for the parent domain
    const filteredTrustPreferenceEntries = filterTrustPreferenceEntries(config.get("policy-trust-preference"), parentDomain);

    // get policies whose PCAs have the highest trust level (II)
    const {highestTrustLevel, highestTrustLevelPolicies} = policyFilterHighestTrustLevelPolicies(filteredTrustPreferenceEntries, domainPolicies);

    const trustInfos = [];
    highestTrustLevelPolicies.forEach(({pcaPolicy, originTrustPreference}, pcaIdentifier) => {
        if (pcaPolicy.AllowedSubdomains !== null) {
            let evaluation;
            if (pcaPolicy.AllowedSubdomains.every(d => d !== actualDomain)) {
                evaluation = new PolicyEvaluation(parentDomain, PolicyAttributes.SUBDOMAINS, EvaluationResult.FAILURE, highestTrustLevel, originTrustPreference);
            } else {
                evaluation = new PolicyEvaluation(parentDomain, PolicyAttributes.SUBDOMAINS, EvaluationResult.SUCCESS, highestTrustLevel, originTrustPreference);
            }
            const trustInfo = new PolicyTrustInfo(pcaIdentifier, parentDomain, pcaPolicy, [evaluation]);
            trustInfos.push(trustInfo);
        }
    });

    return {trustInfos};
}

// check connection using the policies retrieved from a single mapserver
// allPolicies has the following structure: {domain: {pca: SP}}, where SP has the structure: {attribute: value}, e.g., {AllowedSubdomains: ["allowed.mydomain.com"]}
export function policyValidateConnection(remoteInfo, config, domainName, allPolicies, mapserver) {
    // iterate over all policies from all (trusted) mapservers
    // for example: the request for video.google.com, will contain the policies for "video.google.com" and "google.com"
    const policyTrustInfos = [];
    allPolicies.forEach((value, key) => {
        if (key == domainName) {
            // validate policies defined on the actual domain (e.g., allowed CA issuers)
            const {trustInfos} = policyValidateActualDomain(remoteInfo, config, key, value);
            policyTrustInfos.push(...trustInfos);
        } else if (domainFunc.getParentDomain(domainName) == key) {
            // validate policies defined on the parent domain (e.g., allowed subdomains)
            const {trustInfos} = policyValidateParentDomain(remoteInfo, config, domainName, key, value);
            policyTrustInfos.push(...trustInfos);
        } else {
            // TODO: how to deal with violations of other ancestors (e.g., parent of parent)?
        }
    });
    const trustDecision = new PolicyTrustDecision(mapserver, domainName, remoteInfo.certificates[0], remoteInfo.certificates.slice(1), policyTrustInfos);

    trustDecision.mergeIdenticalPolicies();

    return {trustDecision};
}

function filterTrustPreferenceEntries(trustPreferenceEntries, domain) {
    const filteredTrustPreferenceEntries = [];
    trustPreferenceEntries.forEach((tpEntry, d) => {
        if (!d.includes("*")) {
            if (d === domain) {
                filteredTrustPreferenceEntries.push(tpEntry);
            }
        } else {
            if (d[0] === "*" && (d.length === 1 || d[1] === ".") && !d.substr(1).includes("*")) {
                if (d.length === 1 || domain.endsWith(d.substr(2))) {
                    filteredTrustPreferenceEntries.push(tpEntry);
                }
            } else {
                throw new FpkiError(INVALID_CONFIG, "invalid wildcard domain descriptor (must start with *, cannot use wildcards on partial domains (e.g., *example.com))");
            }
        }
    });
    return filteredTrustPreferenceEntries;
}

function legacyValidateActualDomain(connectionTrustInfo, config, actualDomain, domainCertificates) {
    const CertificateException = "[legacy mode] more highly trusted CA detected";

    const caSets = config.get("ca-sets");

    const trustInfos = [];

    const filteredTrustPreferenceEntries = filterTrustPreferenceEntries(config.get("legacy-trust-preference"), actualDomain);

    if (filteredTrustPreferenceEntries.length === 0) {
        return {trustInfos};
    }

    const connectionCert = connectionTrustInfo.cert;
    const connectionRootCertSubject = connectionTrustInfo.certChain[connectionTrustInfo.certChain.length-1].subject
    const connectionRootCertTrustLevel = connectionTrustInfo.rootCaTrustLevel;

    // get cert whose root cert has the highest trust level (II)
    let highestTrustLevelCerts = [];
    let highestTrustLevelCertChains = [];
    let highestTrustLevelRootCertSubject = [];
    let highestTrustLevelRootCertTrustLevel = 0;
    let highestTrustLevelTrustPreferences =[];
    domainCertificates.forEach(({certs, certChains}, caIdentifier) => {
        certs.forEach((cert, index) => {
            filteredTrustPreferenceEntries.forEach(tps => {
                tps.forEach(tp => {
                    // TODO: correctly do the check from CN value to full subject (maybe add "CN="+caIdentifer+",") or parse all subject attributes
                    if (caSets.get(tp.caSet).some(s => s.includes(caIdentifier))) {
                        if (tp.level > highestTrustLevelRootCertTrustLevel) {
                            highestTrustLevelCerts = [cert];
                            highestTrustLevelCertChains = [certChains[index]];
                            highestTrustLevelRootCertSubject = [caIdentifier];
                            highestTrustLevelTrustPreferences = [tp];
                            highestTrustLevelRootCertTrustLevel = tp.level;
                        }
                        else if (tp.level === highestTrustLevelRootCertTrustLevel) {
                            highestTrustLevelCerts.push(cert);
                            highestTrustLevelCertChains.push(certChains[index]);
                            highestTrustLevelRootCertSubject.push(caIdentifier);
                            highestTrustLevelTrustPreferences.push(tp);
                        }
                    }
                });
            });
        });
    });
    highestTrustLevelCerts.forEach(cert => {
        console.log("SUB: " + getSubject(cert));
    });


    // if I >= II then fine
    // else
    //   if pub key (I) == pub key (II) then fine
    //   else abort
    if (connectionRootCertTrustLevel < highestTrustLevelRootCertTrustLevel) {
        highestTrustLevelCerts.forEach((c, idx) => {
            // TODO: check for identical public keys, in which case we can still continue with the certificate provided by the connection
            // https://stackoverflow.com/questions/18338890/are-there-any-sha-256-javascript-implementations-that-are-generally-considered-t
            // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
            // await crypto.subtle.digest('SHA-256', c.tbsCertificate.subjectPublicKeyInfo);
            const publicKeyDiffers = true;
            if (publicKeyDiffers) {
                trustInfos.push(new LegacyTrustInfo(c, highestTrustLevelCertChains[idx], highestTrustLevelRootCertTrustLevel, highestTrustLevelTrustPreferences[idx], CertificateException));
            }
        });
    }
    return {trustInfos};
}

// check connection using the policies retrieved from a single mapserver
// allPolicies has the following structure: {domain: {pca: SP}}, where SP has the structure: {attribute: value}, e.g., {AllowedSubdomains: ["allowed.mydomain.com"]}
export function legacyValidateConnection(remoteInfo, config, domainName, allCertificates, mapserver) {
    // iterate over all certificates from all (trusted) mapservers
    // for example: the request for video.google.com, will only contain the certificates for "video.google.com"
    // TODO: currently all certificates are included in the response, could not return certificates for the parent domain in the future

    // get connection cert
    // TODO: ensure that the first certificate is always the actual certificate
    let connectionCert = remoteInfo.certificates[0];

    // get connection root cert
    let connectionRootCertSubject = null;
    remoteInfo.certificates.forEach((certificate, i) => {
        if (certificate.isBuiltInRoot) {
            connectionRootCertSubject = certificate.subject;
        }
    });

    const caSets = config.get("ca-sets");
    const filteredTrustPreferenceEntries = filterTrustPreferenceEntries(config.get("legacy-trust-preference"), domainName);

    // get connection root cert trust level (I)
    let connectionRootCertTrustLevel = 0;
    let connectionOriginTrustPreference = null;
    filteredTrustPreferenceEntries.forEach(tps => {
        tps.forEach(tp => {
            if (caSets.get(tp.caSet).includes(connectionRootCertSubject)) {
                if (tp.level > connectionRootCertTrustLevel) {
                    connectionRootCertTrustLevel = tp.level;
                    connectionOriginTrustPreference = tp;
                }
            }
        });
    });

    const connectionTrustInfo = new LegacyTrustInfo(connectionCert, remoteInfo.certificates.slice(1), connectionRootCertTrustLevel, connectionOriginTrustPreference, null);
    const certificateTrustInfos = [];
    allCertificates.forEach((value, key) => {
        if (key == domainName) {
            // validate based on certificates for the actual domain
            const {trustInfos} = legacyValidateActualDomain(connectionTrustInfo, config, key, value);
            certificateTrustInfos.push(...trustInfos);
        } else {
            // TODO: how to deal with certificate violations of other ancestors (e.g., parent of parent)?
        }
    });
    const trustDecision = new LegacyTrustDecision(mapserver, domainName, connectionTrustInfo, certificateTrustInfos);

    return {trustDecision};
}
