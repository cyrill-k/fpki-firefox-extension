'use strict'

import * as domainFunc from "../js_lib/domain.js"

const cancelUrl = chrome.runtime.getURL('/pages/block.html')

function checkCert() {
    return true
}

async function checkInfo(details) {
    console.log("hi")
    const remoteInfo = await browser.webRequest.getSecurityInfo(details.requestId, {
        certificateChain: true,
        rawDER: true
    })

    try {
        console.log(domainFunc.getDomainNameFromURL(details.url))
    } catch (error) {
        console.error(error);
        // expected output: ReferenceError: nonExistentFunction is not defined
        // Note - error messages will vary depending on browser
    }

    //console.log(remoteInfo.certificates[0].rawDER)

    //if (checkCert()){
    //    return {redirectUrl: cancelUrl}
    //}
}


browser.webRequest.onHeadersReceived.addListener(
    checkInfo, {
    urls: ["https://www.google.com/"]
},
    ['blocking'])