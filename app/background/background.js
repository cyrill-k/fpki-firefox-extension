'use strict'

import * as domainFunc from "../js_lib/domain.js"
import * as LFPKI_accessor from "../js_lib/LF-PKI-accessor.js"

const cancelUrl = chrome.runtime.getURL('/pages/block.html')

async function checkInfo(details) {
    const remoteInfo = await browser.webRequest.getSecurityInfo(details.requestId, {
        certificateChain: true,
        rawDER: true
    })

    try {
        await LFPKI_accessor.getMapServerResponseAndAnalyse(details.url, true)
    }
    catch (error) {
        console.error(error)
    }
}


browser.webRequest.onHeadersReceived.addListener(
    checkInfo, {
    urls: ["https://www.google.com/", "https://www.baidu.com/"]
},
    ['blocking'])