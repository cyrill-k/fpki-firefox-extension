import * as domainFunc from "./domain.js"

function policyValidateActualDomain(remoteInfo, config, actualDomain, domainPolicies) {
    var CertificateException = "invalid CA";

    // countries to CA map
    // map countries => CAs in that country
    let countryToCAMap = new Map();
    countryToCAMap.set("US CA", ["CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
                                 "CN=GTS Root R1,O=Google Trust Services LLC,C=US",
                                 "CN=Amazon,OU=Server CA 1B,O=Amazon,C=US",
                                 "CN=Amazon Root CA 1,O=Amazon,C=US",
                                 "CN=DigiCert Global CA G2,O=DigiCert Inc,C=US",
                                 "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US"]);
    
    const violations = [];
    domainPolicies.forEach((pcaPolicy, pcaIdentifier) => {
        if (pcaPolicy.TrustedCA !== null) {
            remoteInfo.certificates.forEach((certificate, i) => {
                // if certificate is in browsers trust store
                if (certificate.isBuiltInRoot) {
                    // check if CA is in the trusted list
                    if (pcaPolicy.TrustedCA.every(ca => !countryToCAMap.get(ca).includes(certificate.subject))) {
                        violations.push({pca: pcaIdentifier, reason: CertificateException + ": " + certificate.issuer});
                    }
                }
            });
        }
    });
    return {success: violations.length === 0, violations};
}

function policyValidateParentDomain(remoteInfo, config, actualDomain, parentDomain, domainPolicies) {
    var DomainNotAllowed = "domain not allowed";

    const violations = [];
    let domainIsDisallowed = false;
    domainPolicies.forEach((pcaPolicy, pcaIdentifier) => {
        if (pcaPolicy.AllowedSubdomains !== null) {
            if (pcaPolicy.AllowedSubdomains.every(d => d !== actualDomain)) {
                violations.push({pca: pcaIdentifier, reason: DomainNotAllowed + ": " + actualDomain});
            }
        }
    });

    return {success: violations.length === 0, violations};
}

// check connection using the policies retrieved from a single mapserver
// allPolicies has the following structure: {domain: {pca: SP}}, where SP has the structure: {attribute: value}, e.g., {AllowedSubdomains: ["allowed.mydomain.com"]}
export function policyValidateConnection(remoteInfo, config, domainName, allPolicies) {
    // iterate over all policies from all (trusted) mapservers
    // for example: the request for video.google.com, will contain the policies for "video.google.com" and "google.com"
    const violations = [];
    allPolicies.forEach((value, key) => {
        if (key == domainName) {
            // validate policies defined on the actual domain (e.g., allowed CA issuers)
            const {success, violations: actualDomainViolations} = policyValidateActualDomain(remoteInfo, config, key, value);
            violations.push(...actualDomainViolations);
        } else if (domainFunc.getParentDomain(domainName) == key) {
            // validate policies defined on the parent domain (e.g., allowed subdomains)
            const {success, violations: parentDomainViolations} = policyValidateParentDomain(remoteInfo, config, domainName, key, value);
            violations.push(...parentDomainViolations);
        } else {
            // TODO: how to deal with violations of other ancestors (e.g., parent of parent)?
        }
    });
    return {success: violations.length === 0, violations};
}
