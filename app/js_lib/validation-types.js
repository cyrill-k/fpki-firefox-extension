import {errorTypes, FpkiError} from "./errors.js"
import {mapGetList} from "./helper.js"
import {getSubject} from "./x509utils.js"

// holds the assessed trust info (the trust level of the root certificate and the trust preference where this trust level was derived from) of a certain certificate (either received via TLS handshake or via a mapserver).
//
// If this object describes the trust info of a certificate from a mapserver, it additionally includes possible violations regarding the TLS certificate (e.g., it is signed by a more highly trusted CA)
export class LegacyTrustInfo {
    constructor(cert, certChain, rootCaTrustLevel, originTrustPreference, violation) {
        this.cert = cert;
        this.certChain = certChain;
        this.rootCaTrustLevel = rootCaTrustLevel;
        this.originTrustPreference = originTrustPreference;
        this.violation = violation;
        this.evaluationResult = EvaluationResult.FAILURE;
    }
}

// combines trust information of multiple certificates issued for a given domain from a single mapserver
export class LegacyTrustDecision {
    constructor(mapserver, domain, connectionTrustInfo, certificateTrustInfos) {
        this.type = "legacy";
        this.mapserver = mapserver;
        this.domain = domain;
        this.connectionTrustInfo = connectionTrustInfo;
        this.certificateTrustInfos = certificateTrustInfos;
        this.decision = hasFailedValidations(this) ? "negative" : "positive";
    }

    // maybe we don't need to merge because we always stop as soon as the first negative decision is made
    merge(other) {
        if (this.domain !== other.domain) {
            throw new FpkiError(errorTypes.INTERNAL_ERROR, "Merging trust decisions for different domains");
        }
        if (this.connectionTrustInfo !== other.connectionTrustInfo) {
            throw new FpkiError(errorTypes.INTERNAL_ERROR, "Merging trust decisions for different certificates");
        }
        this.certificateTrustInfos.push(...other.certificateTrustInfos);
    }
}

export class PolicyTrustDecisionGo {
    constructor(domain, evaluationResult, policyChain, conflictingPolicies, validUntilUnix, domainExcluded) {
        this.type = "policy";
        this.domain = domain;
        this.connectionCertificateChain = null;

        this.evaluationResult = evaluationResult;

        // timestamp until which this entry can be cached
        this.validUntil = new Date(validUntilUnix*1000);

        this.policyChain = policyChain;

        this.conflictingPolicies = conflictingPolicies;

        this.domainExcluded = domainExcluded;
    }
}

export class LegacyTrustDecisionGo {
    constructor(domain, connectionTrustLevel, connectionTrustLevelCASet, connectionTrustLevelChainIndex, evaluationResult,
                highestTrustLevel, highestTrustLevelCASets, highestTrustLevelChainIndices, highestTrustLevelChainHashes, highestTrustLevelChainSubjects, validUntilUnix) {

        // information describing the certificate obtained in the
        // handshake and its trust level
        this.type = "legacy";
        this.domain = domain;
        this.connectionCertificateChain = null;
        this.connectionTrustLevel = connectionTrustLevel;
        this.connectionTrustLevelCASet = connectionTrustLevelCASet;
        this.connectionTrustLevelChainIndex = connectionTrustLevelChainIndex;

        // outcome of the legacy validation
        this.evaluationResult = evaluationResult;

        // highest trust level detected in the cache for this domain
        this.highestTrustLevel = highestTrustLevel;

        // information describing why legacy validation failed
        // lists consisting of CA Set IDs and corresponding 
        // chain indices found in cached certificates that led
        // to the failure
        this.highestTrustLevelCASets = highestTrustLevelCASets;
        this.highestTrustLevelChainIndices = highestTrustLevelChainIndices;
        this.highestTrustLevelChainHashes = highestTrustLevelChainHashes
        this.highestTrustLevelChainSubjects = highestTrustLevelChainSubjects

        // timestamp until which this entry can be cached
        this.validUntil = new Date(validUntilUnix*1000);
    }
}

export const PolicyAttributes = {
    TRUSTED_CA: "Trusted CA",
    SUBDOMAINS: "Subdomains"
};

export const AllPolicyAttributes = [
    PolicyAttributes.TRUSTED_CA,
    PolicyAttributes.SUBDOMAINS
];

export const PolicyAttributeToJsonKeyDict = {
    [PolicyAttributes.TRUSTED_CA]: "TrustedCA",
    [PolicyAttributes.SUBDOMAINS]: "AllowedSubdomains"
}

export const EvaluationResult = {
    SUCCESS: "success",
    FAILURE: "failure"
};

// contains an evaluation result for a certain policy evaluated over a specific domain (i.e., the domain that was queried or one of its ancestor domains)
export class PolicyEvaluation {
    constructor(domain, attribute, evaluationResult, trustLevel, originTrustPreference) {
        this.domain = domain;
        this.attribute = attribute;
        this.evaluationResult = evaluationResult;
        this.trustLevel = trustLevel;
        this.originTrustPreference = originTrustPreference;
    }
}

// combines multiple policy evaluation results for a single policy.
// For example, there might be an evaluation result for the allowed subdomains and for the allowed issuers
export class PolicyTrustInfo {
    constructor(pca, policyDomain, policyAttributes, evaluations) {
        this.pca = pca;
        this.policyDomain = policyDomain;
        this.policyAttributes = policyAttributes;
        this.evaluations = evaluations;
    }
}

export function hasApplicablePolicy(policyTrustDecision) {
    return policyTrustDecision.policyTrustInfos.some(pti => pti.evaluations.length > 0);
}

export function hasFailedValidations(trustDecision) {
    if (trustDecision.type === "policy") {
        return trustDecision.policyTrustInfos.some(pti => pti.evaluations.some(e => e.evaluationResult === EvaluationResult.FAILURE));
    } else {
        return trustDecision.certificateTrustInfos.some(cti => cti.evaluationResult === EvaluationResult.FAILURE);
    }
}

export function getShortErrorMessages(trustDecision) {
    const errorMessages = [];
    let trustInfos;
    if (trustDecision.type === "policy") {
        trustInfos = trustDecision.policyTrustInfos;
    } else {
        trustInfos = trustDecision.certificateTrustInfos;
    }
    trustInfos.forEach(ti => {
        if (trustDecision.type === "policy") {
            ti.evaluations.forEach(e => {
                errorMessages.push(getPolicyErrorMessage(trustDecision, ti, e));
            });
        } else {
            errorMessages.push(getLegacyErrorMessage(trustDecision, ti));
        }
    });
    return errorMessages;
}

export function getLegacyValidationErrorMessageGo(legacyTrustDecisionGo) {
    let errorMessage = "";
    errorMessage += "Detected " + legacyTrustDecisionGo.highestTrustLevelCASets.length +" more highly trusted certificate chains than the chain received in the connection.";
    if (legacyTrustDecisionGo.connectionTrustLevelCASet === "DEFAULT") {
        errorMessage += " Connection certificate chain has the default trust level " + legacyTrustDecisionGo.connectionTrustLevel + ".";
    } else {
        errorMessage += " Connection certificate chain has trust level " + legacyTrustDecisionGo.connectionTrustLevel + " due to certificate \"";
        errorMessage += legacyTrustDecisionGo.connectionCertificateChain[legacyTrustDecisionGo.connectionTrustLevelChainIndex].subject + "\" within CA Set: " + legacyTrustDecisionGo.connectionTrustLevelCASet + ".";
    }
    for(let i = 0; i < legacyTrustDecisionGo.highestTrustLevelCASets.length; i++) {
        errorMessage += " Detected certificate chain with trust level " + legacyTrustDecisionGo.highestTrustLevel;
        console.log(legacyTrustDecisionGo.highestTrustLevelChainSubjects);
        console.log(legacyTrustDecisionGo.relevantCertificateChainIndex);
        errorMessage += " due to certificate \"" + legacyTrustDecisionGo.highestTrustLevelChainSubjects[i][legacyTrustDecisionGo.highestTrustLevelChainIndices[i]] + "\" within CA Set " + legacyTrustDecisionGo.highestTrustLevelCASets[i] + ".";
    }

    return errorMessage;
}

export function getPolicyValidationErrorMessageGo(policyTrustDecisionGo) {
    const policyChainDescriptors = getPolicyChainDescriptors(policyTrustDecisionGo.policyChain);
    let m = "";
    m += "Detected violated policies ";
    m += policyTrustDecisionGo.conflictingPolicies.map(JSON.parse).map(p => `${JSON.stringify(p.Attribute)} [${p.Domain}]`).join(", ");
    m += " specified in chain ";
    m += policyChainDescriptors.toReversed().map(d => `"${d}"`).join(" => ");
    return m;
}

// returns a list of human understandable descriptors of certificates in policy chains
export function getPolicyChainDescriptors(chain) {
    let isFirstNonEmptyDomain = true;
    let certCounter;
    let descriptors = [];
    chain.toReversed().forEach((pJson, index) => {
        const p = JSON.parse(pJson).O;
        let desc = "";
        if (index === 0) {
            desc = "PCA root";
            certCounter = 1;
        } else if (!("Domain" in p)) {
            desc = "PCA intermediate " + certCounter;
            certCounter += 1;
        } else if (isFirstNonEmptyDomain) {
            isFirstNonEmptyDomain = false;
            desc = "Domain root [" + p.Domain + "]";
            certCounter = 1;
        } else {
            desc = "Domain intermediate " + certCounter + " [" + p.Domain + "]";
            certCounter += 1;
        }
        descriptors = [desc, ...descriptors];
    });
    return descriptors;
}

function getPolicyErrorMessage(trustDecision, trustInfo, evaluation) {
    let errorMessage = "";
    errorMessage += "[policy mode] ";
    if (evaluation.attribute === PolicyAttributes.TRUSTED_CA) {
        errorMessage += "Detected certificate issued by an invalid CA: "+getSubject(trustDecision.connectionCertChain[trustDecision.connectionCertChain.length-1]);
    } else if (evaluation.attribute === PolicyAttributes.SUBDOMAINS) {
        errorMessage += "Detected certificate issued for a domain that is not allowed: "+trustDecision.domain;
    }
    errorMessage += " [policy issued by PCA: ";
    errorMessage += trustInfo.pca;
    errorMessage += "]";
    return errorMessage;
}

function getLegacyErrorMessage(trustDecision, trustInfo) {
    let errorMessage = "";
    errorMessage += "[legacy mode] Detected certificate issued by a CA that is more highly trusted than ";
    errorMessage += getSubject(trustDecision.connectionTrustInfo.certChain[trustDecision.connectionTrustInfo.certChain.length-1]);
    errorMessage += " [certificate issued by CA: ";
    if (trustInfo.certChain.length === 0) {
        errorMessage += "unknown";
    } else {
        errorMessage += getSubject(trustInfo.certChain[trustInfo.certChain.length-1]);
    }
    errorMessage += "]";
    return errorMessage;
}

// combines trust information of multiple policies (possibly issued by different PCAs) issued for a given domain from a single mapserver
export class PolicyTrustDecision {
    constructor(mapserver, domain, connectionCert, connectionCertChain, policyTrustInfos, decision="negative") {
        this.type = "policy";
        this.mapserver = mapserver;
        this.domain = domain;
        this.connectionCert = connectionCert;
        this.connectionCertChain = connectionCertChain;
        this.policyTrustInfos = policyTrustInfos;
        this.decision = hasFailedValidations(this) ? "negative" : "positive";
    }

    mergeIdenticalPolicies() {
        const newKeys = this.policyTrustInfos.map(ti => {
            return {pca: ti.pca, policy: ti.policy};
        });
        const policyMap = new Map();
        this.policyTrustInfos.forEach(ti => {
            const policyWithPca = {pca: ti.pca, policyDomain: ti.policyDomain, policyAttributes: ti.policyAttributes};
            const policyWithPcaStr = JSON.stringify(policyWithPca, (key, value) => {
                return value;
                // if (!key || key === "pca" || key === "policyDomain" || key === "policyAttributes" || key === "TrustedCA" || key === "AllowedSubdomains" || Array.isArray(value) || !isNaN(key)) {
                    // return value;
                // } else {
                    // return undefined;
                // }
            });
            policyMap.set(policyWithPcaStr, mapGetList(policyMap, policyWithPcaStr).concat(ti.evaluations));
        });
        this.policyTrustInfos = Array.from(policyMap.entries()).map(([policyWithPcaStr, evaluations]) => {
            const {pca, policyDomain, policyAttributes} = JSON.parse(policyWithPcaStr);
            return new PolicyTrustInfo(pca, policyDomain, policyAttributes, evaluations);
        });
    }
}
