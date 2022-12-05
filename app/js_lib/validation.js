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

function legacyValidateActualDomain(remoteInfo, config, actualDomain, domainCertificates) {
    var CertificateException = "[legacy mode] more highly trusted CA detected";

    // countries to CA map
    // map countries => CAs in that country
    let countryToCAMap = new Map();
    countryToCAMap.set("US CA", ["CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
                                 "CN=GTS Root R1,O=Google Trust Services LLC,C=US",
                                 "CN=Amazon,OU=Server CA 1B,O=Amazon,C=US",
                                 "CN=Amazon Root CA 1,O=Amazon,C=US",
                                 "CN=DigiCert Global CA G2,O=DigiCert Inc,C=US",
                                 "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US"]);

    let legacyTrustPreference = new Map();
    legacyTrustPreference.set("google.com", [{caSet: "US CA", level: 1}]);
    legacyTrustPreference.set("qq.com", [{caSet: "US CA", level: 1}]);
    // TODO: implement wildcard trust preferences

    const violations = [];

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

    // get connection root cert trust level (I)
    if (!legacyTrustPreference.has(actualDomain)) {
        return {success: true, violations};
    }
    let connectionRootCertTrustLevel = 0;
    legacyTrustPreference.get(actualDomain).forEach(tp => {
        if (countryToCAMap.get(tp.caSet).includes(connectionRootCertSubject)) {
            if (tp.level > connectionRootCertTrustLevel) {
                connectionRootCertTrustLevel = tp.level;
            }
        }
    });

    // get cert whose root cert has the highest trust level (II)
    let highestTrustLevelCerts = [];
    let highestTrustLevelRootCertSubjectCN = [];
    let highestTrustLevelRootCertTrustLevel = 0;
    domainCertificates.forEach((caCertificates, caIdentifier) => {
        caCertificates.forEach(caCertificate => {
            legacyTrustPreference.get(actualDomain).forEach(tp => {
                // TODO: correctly do the check from CN value to full subject (maybe add "CN="+caIdentifer+",") or parse all subject attributes
                if (countryToCAMap.get(tp.caSet).some(s => s.includes(caIdentifier))) {
                    if (tp.level > highestTrustLevelRootCertTrustLevel) {
                        highestTrustLevelCerts = [caCertificate];
                        highestTrustLevelRootCertSubjectCN = [caIdentifier];
                        highestTrustLevelRootCertTrustLevel = tp.level;
                    }
                    else if (tp.level === highestTrustLevelRootCertTrustLevel) {
                        highestTrustLevelCerts.push(caCertificate);
                        highestTrustLevelRootCertSubjectCN.push(caIdentifier);
                    }
                }
            });
        });
    });

    console.log("outcome");
    console.log(connectionRootCertSubject);
    console.log(connectionRootCertTrustLevel);
    console.log(highestTrustLevelCerts);
    console.log(highestTrustLevelRootCertSubjectCN);
    console.log(highestTrustLevelRootCertTrustLevel);
    console.log(connectionCert);

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
                violations.push({ca: connectionRootCertSubject, reason: CertificateException + ": " + highestTrustLevelRootCertSubjectCN[idx]});
            }
        });
    }
    return {success: violations.length === 0, violations};
}

// check connection using the policies retrieved from a single mapserver
// allPolicies has the following structure: {domain: {pca: SP}}, where SP has the structure: {attribute: value}, e.g., {AllowedSubdomains: ["allowed.mydomain.com"]}
export function legacyValidateConnection(remoteInfo, config, domainName, allCertificates) {
    // iterate over all certificates from all (trusted) mapservers
    // for example: the request for video.google.com, will only contain the certificates for "video.google.com"
    // TODO: currently all certificates are included in the response, could not return certificates for the parent domain in the future
    const violations = [];
    allCertificates.forEach((value, key) => {
        if (key == domainName) {
            // validate based on certificates for the actual domain
            const {success, violations: actualDomainViolations} = legacyValidateActualDomain(remoteInfo, config, key, value);
            violations.push(...actualDomainViolations);
        } else {
            // TODO: how to deal with certificate violations of other ancestors (e.g., parent of parent)?
        }
    });
    return {success: violations.length === 0, violations};
}
