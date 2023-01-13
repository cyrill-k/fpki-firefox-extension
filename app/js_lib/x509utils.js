import {errorTypes, FpkiError} from "./errors.js"

// imports the function ParsePemCertificate as an object of the global variable certificateparser
import * as mymodule from "./bundledparser.js"

export function parsePemCertificate(pemData, addHeaderAndFooter=false) {
    if (addHeaderAndFooter) {
        return certificateparser.parsePemCertificate("-----BEGIN CERTIFICATE-----\n"+pemData+"\n-----END CERTIFICATE-----");
    } else {
        return certificateparser.parsePemCertificate(pemData);
    }
}

// extracts the subject of a certificate which is either in the https://github.com/indutny/asn1.js/tree/master/rfc/5280 format or the MDN format
export function getSubject(cert) {
    if ("subject" in cert) {
        return cert.subject;
    } else {
        return convertX509NameToString(cert.tbsCertificate.subject);
    }
}

export function getIssuer(cert) {
    if ("issuer" in cert) {
        return cert.issuer;
    } else {
        return convertX509NameToString(cert.tbsCertificate.issuer);
    }
}

function convertX509NameToString(x509Name) {
    const attributeTypeNames = new Map(Object.entries({
	"2.5.4.6":  "C",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
	"2.5.4.3":  "CN",
	"2.5.4.5":  "SERIALNUMBER",
	"2.5.4.7":  "L",
	"2.5.4.8":  "ST",
	"2.5.4.9":  "STREET",
	"2.5.4.17": "POSTALCODE",
    }));

    const attributeDict = new Map();
    x509Name.value.forEach(kv => {
        let combinedValues = "";
        kv.forEach(({value: derValue}, vIndex) => {
            if (vIndex > 0) {
                combinedValues += "+";
            }
            let escapedValue = "";

            const v = certificateparser.parseDerName(derValue).value;
            // console.log(v);
            for (let cIndex = 0; cIndex < v.length; cIndex++) {
                const c = v[cIndex];
            // for (const c of value) {
                // value.forEach((c, cIndex) => {
                let escape = false;
                switch(c) {
                case ',':
                case '+':
                case '"':
                case '\\':
                case '<':
                case '>':
                case ';':
                    escape = true;
                    break;
                case ' ':
                    escape = cIndex === 0 || cIndex === v.length-1;
                    break;
                case '#':
                    escape = cIndex === 0
                    break;
                }
                if (escape) {
                    escapedValue += '\\' + c;
                } else {
                    escapedValue += c;
                }
            }
            combinedValues += escapedValue;
        });
        const oidString = kv[0].type.join(".");
        if (!attributeTypeNames.has(oidString)) {
            throw new FpkiError(errorTypes.INTERNAL_ERROR, "Invalid OID used in X509 certificate field");
        }
        const attributeName = attributeTypeNames.get(oidString);
        attributeDict.set(attributeName, combinedValues);
    });
    const typeOrder = ["SERIALNUMBER", "CN", "OU", "O", "POSTALCODE", "STREET", "L", "ST", "C"];
    return typeOrder.
        filter(t => attributeDict.has(t)).
        map(t => t + "=" + attributeDict.get(t)).
        join(",");
}
