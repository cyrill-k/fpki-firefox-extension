async function verifyProofs(domainEntryList) {
    try {
        for (var i = 0; i < domainEntryList.length; i++) {
            let isCorrect = await verifyProof(domainEntryList[i])
            if (!isCorrect) {
                console.log("error")
                return false
            }
        }
        console.log("succeed")
        return true
    } catch (error) {
        console.error(error)
    }
}


async function verifyProof(domainEntry) {
    try {
        let keyHash = await sha256Hash_1(domainEntry.Domain)
        let leafHash = await sha256Hash_1(domainEntry.DomainEntryBytes)

        verifyInclusion(domainEntry.PoI, keyHash, leafHash)
        return true
    } catch (error) {
        console.error(error)
    }
}

async function verifyInclusion(PoI, keyHash, valueHash) {
    try {
        let root = _base64ToArrayBuffer(PoI.Root)
        //console.log("raw root", PoI.Root)
        console.log("decoded ", new Uint8Array(root))
        //console.log("root", new Uint8Array(stringToArrayBuf(root)))

        let depthArrayBuf = new ArrayBuffer(1)
        let depthView = new Uint8Array(depthArrayBuf)
        depthView[0] = 256 - PoI.Proof.length

        let keyView = new Uint8Array(keyHash)

        let leafHash = await sha256Hash_3(keyHash, valueHash, depthArrayBuf)

        for (var i = PoI.Proof.length - 1; i >= 0; i--) {
            let proofDecoded = _base64ToArrayBuffer(PoI.Proof[PoI.Proof.length - 1 - i])
           // console.log("ap index", PoI.Proof.length - 1 - i)
           // console.log("ap raw", PoI.Proof[PoI.Proof.length - 1 - i])
           // console.log("ap decoded ", proofDecoded)
            if (!bitIsSet(keyView, i)) {
             //  console.log("left", new Uint8Array(proofDecoded))
              //  console.log("right", new Uint8Array(leafHash))
                leafHash = await sha256Hash_2(proofDecoded, leafHash)
            } else {
               // console.log("left", new Uint8Array(leafHash))
               // console.log("right", new Uint8Array(proofDecoded))
                leafHash = await sha256Hash_2(leafHash, proofDecoded)
            }
            //console.log("hash at level ", i, new Uint8Array(leafHash))
        }
       console.log("final hash", new Uint8Array(leafHash))
        
    } catch (error) {
        console.error(error)
    }
}


/*
// VerifyInclusion verifies that key/value is included in the trie with latest root
func VerifyInclusion(root[]byte, ap[][]byte, key, value[]byte) bool {
    leafHash:= common.SHA256Hash(key, value, []byte{ byte(256 - len(ap))
})
return bytes.Equal(root, verifyInclusion(ap, 0, key, leafHash))
}

// verifyInclusion returns the merkle root by hashing the merkle proof items
func verifyInclusion(ap[][]byte, keyIndex int, key, leafHash[]byte)[]byte {
    if keyIndex == len(ap) {
        return leafHash
    }
    if bitIsSet(key, keyIndex) {
        return common.SHA256Hash(ap[len(ap) - keyIndex - 1], verifyInclusion(ap, keyIndex + 1, key, leafHash))
    }
    return common.SHA256Hash(verifyInclusion(ap, keyIndex + 1, key, leafHash), ap[len(ap) - keyIndex - 1])
}

*/

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
    try {
        let bitIndex = index % 8
        let uint8Index = (index - bitIndex) / 8
        var mask = 1 << bitIndex

        if ((keyView[uint8Index] & mask) != 0) {
          //  console.log(true)
            return true
        } else {
            //console.log(false)
            return false
        }
    } catch (error) {
        console.error(error)
    }
}



async function verifyNonInclusion() {

}


function encode_utf8(s) {
    return unescape(encodeURIComponent(s));
}

/*
function stringToArrayBuf(str) {

    var enc = new TextEncoder()
    return enc.encode(str)
}*/

function stringToArrayBuf(str) {
    var s = encode_utf8(str)
    var buf = new ArrayBuffer(s.length);
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen = s.length; i < strLen; i++) {
        bufView[i] = s.charCodeAt(i)
    }
    return buf;
}

function appendTwoArrayBuf(str1, str2) {
    let str1View = new Uint8Array(str1)
    let str2View = new Uint8Array(str2)
    try {
        var buf = new ArrayBuffer(str1View.length + str2View.length);
        var bufView = new Uint8Array(buf);
        for (var i = 0, strLen = str1View.length; i < strLen; i++) {
            bufView[i] = str1View[i];
        }
        for (var i = 0, strLen = str2View.length; i < strLen; i++) {
            bufView[i + str1View.length] = str2View[i];
        }
        return buf;
    } catch (error) {
        console.error(error)
    }
}

function appendThreeArrayBuf(str1, str2, str3) {
    //console.log("key", new Uint8Array(str1))
    //console.log("value",new Uint8Array(str2))
    //console.log("depth",new Uint8Array(str3))

    let str1View = new Uint8Array(str1)
    let str2View = new Uint8Array(str2)
    let str3View = new Uint8Array(str3)
    try {
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
    } catch (error) {
        console.error(error)
    }
}


export {
    verifyProofs
}