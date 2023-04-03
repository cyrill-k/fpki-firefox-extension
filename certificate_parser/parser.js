const rfc5280 = require('asn1.js-rfc5280');
const jseu = require('js-encoding-utils');
const Buffer = require('buffer').Buffer;

// pass the certificate in the PEM format and return a certificate object
function parsePemCertificate(pemCertificate) {
    const x509bin = jseu.formatter.pemToBin(pemCertificate);
    const binKeyBuffer = Buffer.from(x509bin);
    const decoded = rfc5280.Certificate.decode(binKeyBuffer, 'der');
    return decoded;
}

function parseDerName(derName) {
    return rfc5280.DirectoryString.decode(Buffer.from(derName));
}

function getSubjectPublicKeyInfoDER(certificate) {
    return rfc5280.SubjectPublicKeyInfo.encode(certificate.tbsCertificate.subjectPublicKeyInfo, 'der');
}

module.exports = {parsePemCertificate, parseDerName, getSubjectPublicKeyInfoDER};
