import {errorTypes, FpkiError} from "./errors.js"
import {mapGetList} from "./helper.js"

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
    }
}

// combines trust information of multiple certificates issued for a given domain from a single mapserver
export class LegacyTrustDecision {
    constructor(mapserver, domain, connectionTrustInfo, certificateTrustInfos, decision="negative") {
        this.type = "legacy";
        this.decision = decision;
        this.mapserver = mapserver;
        this.domain = domain;
        this.connectionTrustInfo = connectionTrustInfo;
        this.certificateTrustInfos = certificateTrustInfos;
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

export const PolicyAttributes = {
    TRUSTED_CA: "Trusted CA",
    SUBDOMAINS: "Subdomains"
};

export const AllPolicyAttributes = [
    PolicyAttributes.TRUSTED_CA,
    PolicyAttributes.SUBDOMAINS
];

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

// combines trust information of multiple policies (possibly issued by different PCAs) issued for a given domain from a single mapserver
export class PolicyTrustDecision {
    constructor(mapserver, domain, connectionCert, connectionCertChain, policyTrustInfos, decision="negative") {
        this.type = "policy";
        this.decision = decision;
        this.mapserver = mapserver;
        this.domain = domain;
        this.connectionCert = connectionCert;
        this.connectionCertChain = connectionCertChain;
        this.policyTrustInfos = policyTrustInfos;
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
