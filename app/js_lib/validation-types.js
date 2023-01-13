import {errorTypes, FpkiError} from "./errors.js"

export class LegacyTrustInfo {
    constructor(cert, certChain, rootCaTrustLevel, originTrustPreference, violation) {
        this.cert = cert;
        this.certChain = certChain;
        this.rootCaTrustLevel = rootCaTrustLevel;
        this.originTrustPreference = originTrustPreference;
        this.violation = violation;
    }
}

export class LegacyTrustDecision {
    constructor(mapserver, domain, connectionTrustInfo, certificateTrustInfos) {
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
