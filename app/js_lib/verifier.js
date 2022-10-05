// verify the map server response
async function verifyProofs(domainEntryList) {
    var ValidationException = "verification failed"
    // verify all the map server response
    for (var i = 0; i < domainEntryList.length; i++) {
        let isCorrect = await verifyProof(domainEntryList[i])
        if (!isCorrect) {
            throw ValidationException
        }
    }
}

// verify individual map server response
async function verifyProof(domainEntry) {
    let keyHash = await sha256Hash_1(domainEntry.Domain)
    // if it is a PoP
    if (domainEntry.PoI.ProofType == 1) {
        // hash the domain entries, and domain name, to get the key-value pair in the merkle tree
        // NOTE: in the SMT, we store the (domain name hash, domain material hash) as key-value pair
        let leafHash = await sha256Hash_1(domainEntry.DomainEntryBytes)

        // verify the PoP
        if (verifyInclusion(domainEntry.PoI, keyHash, leafHash)) {
            return true
        }
        return false
    }
    else if (domainEntry.PoI.ProofType == 0) {
        // verify the PoA
        if (verifyNonInclusion(domainEntry.PoI, keyHash)) {
            return true
        }
        return false
    }
}

// verify the PoA
async function verifyNonInclusion(PoI, keyHash) {
    if (PoI.ProofKey == null || PoI.ProofKey.length == 0) {
        let defaultLeaf = new Uint8Array(1)
        return verifyInclusion(PoI, keyHash, stringToArrayBuf(defaultLeaf))
    }
    let proofKeyDecoded = _base64ToArrayBuffer(PoI.ProofKey)
    let proofValueDecoded = _base64ToArrayBuffer(PoI.ProofValue)

    return verifyInclusion(PoI, proofKeyDecoded, proofValueDecoded)
}

// verify PoP
async function verifyInclusion(PoI, keyHash, valueHash) {
    let root = _base64ToArrayBuffer(PoI.Root)
    let keyView = new Uint8Array(keyHash)

    // init a depth buffer with 
    let depthArrayBuf = new ArrayBuffer(1)
    let depthView = new Uint8Array(depthArrayBuf)
    depthView[0] = 256 - PoI.Proof.length

    let leafHash = await sha256Hash_3(keyHash, valueHash, depthArrayBuf)

    for (var i = PoI.Proof.length - 1; i >= 0; i--) {
        let proofDecoded = _base64ToArrayBuffer(PoI.Proof[PoI.Proof.length - 1 - i])
        if (!bitIsSet(keyView, i)) {
            leafHash = await sha256Hash_2(proofDecoded, leafHash)
        } else {
            leafHash = await sha256Hash_2(leafHash, proofDecoded)
        }
    }

    if (checkArrayBuffer(leafHash, root)) {
        return true
    }
    return false
}

function checkArrayBuffer(buf1, buf2) {
    if (buf1.byteLength != buf2.byteLength) return false;
    var dv1 = new Int8Array(buf1);
    var dv2 = new Int8Array(buf2);
    for (var i = 0; i != buf1.byteLength; i++) {
        if (dv1[i] != dv2[i]) return false;
    }
    return true;
}

function _base64ToArrayBuffer(base64) {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

async function sha256Hash_1(input) {
    let output = await window.crypto.subtle.digest('SHA-256', stringToArrayBuf(input))
    return output
}

async function sha256Hash_2(input1, input2) {
    let output = await window.crypto.subtle.digest('SHA-256', appendTwoArrayBuf(input1, input2))
    return output
}

async function sha256Hash_3(input1, input2, input3) {
    let output = await window.crypto.subtle.digest('SHA-256', appendThreeArrayBuf(input1, input2, input3))
    return output
}

function bitIsSet(keyView, index) {

    let bitIndex = index % 8
    let uint8Index = (index - bitIndex) / 8
    var mask = 1 << bitIndex

    if ((keyView[uint8Index] & mask) != 0) {
        return true
    } else {
        return false
    }
}

function encode_utf8(s) {
    return unescape(encodeURIComponent(s));
}

function stringToArrayBuf(str) {
    var s = encode_utf8(str)
    var buf = new ArrayBuffer(s.length);
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen = s.length; i < strLen; i++) {
        bufView[i] = s.charCodeAt(i)
    }
    return buf;
}

// append two array buffer; for hashing
function appendTwoArrayBuf(str1, str2) {
    let str1View = new Uint8Array(str1)
    let str2View = new Uint8Array(str2)

    var buf = new ArrayBuffer(str1View.length + str2View.length);
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen = str1View.length; i < strLen; i++) {
        bufView[i] = str1View[i];
    }
    for (var i = 0, strLen = str2View.length; i < strLen; i++) {
        bufView[i + str1View.length] = str2View[i];
    }
    return buf;
}

// append three array buffer; for hashing
function appendThreeArrayBuf(str1, str2, str3) {
    let str1View = new Uint8Array(str1)
    let str2View = new Uint8Array(str2)
    let str3View = new Uint8Array(str3)

    var buf = new ArrayBuffer(str1View.length + str2View.length + str3View.length);
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen = str1View.length; i < strLen; i++) {
        bufView[i] = str1View[i];
    }
    for (var i = 0, strLen = str2View.length; i < strLen; i++) {
        bufView[i + str1View.length] = str2View[i];
    }
    for (var i = 0, strLen = str3View.length; i < strLen; i++) {
        bufView[i + str2View.length + str1View.length] = str3View[i];
    }
    return buf;
}

export {
    verifyProofs
}