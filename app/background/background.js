'use strict'

import * as domainFunc from "../js_lib/domain.js"
import * as LFPKI_accessor from "../js_lib/LF-PKI-accessor.js"

async function checkInfo(details) {
    const remoteInfo = await browser.webRequest.getSecurityInfo(details.requestId, {
        certificateChain: true,
        rawDER: true
    })

    try {
        await LFPKI_accessor.getMapServerResponseAndCheck(details.url, true, remoteInfo, details)
        console.log("succeed!")
    }
    catch (error) {
        console.log(error)
        console.log(chrome.extension.getURL("../htmls/block.html"))

        let { tabId } = details;
        chrome.tabs.update(tabId, {
            url: chrome.extension.getURL("../htmls/block.html") + "?reason=" + error
        })

    }
}

browser.webRequest.onHeadersReceived.addListener(
    checkInfo, {
    urls: ["https://www.google.com/", "https://www.baidu.com/", "https://www.amazon.com/", "https://www.kth.se/en", "https://support.google.com/", "https://docs.google.com/*"]
},
    ['blocking'])