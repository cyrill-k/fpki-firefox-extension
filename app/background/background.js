'use strict'

import * as LFPKI_accessor from "../js_lib/LF-PKI-accessor.js"

async function checkInfo(details) {
    // get remote server information
    const remoteInfo = await browser.webRequest.getSecurityInfo(details.requestId, {
        certificateChain: true,
        rawDER: true
    })

    try {
        // get map server response and check the connection
        await LFPKI_accessor.getMapServerResponseAndCheck(details.url, true, remoteInfo, details)
        console.log("succeed!")
    }
    catch (error) {
        // if any error is caught, redirect to the blocking page, and show the error page
        let { tabId } = details;
        chrome.tabs.update(tabId, {
            url: chrome.extension.getURL("../htmls/block.html") + "?reason=" + error
        })
    }
}

// add listener to header-received. 
browser.webRequest.onHeadersReceived.addListener(
    checkInfo, {
    urls: ["https://www.amazon.com/",
        "https://pay.amazon.com/",
        "https://www.baidu.com/",
        "https://sellercentral.amazon.com/"]
},
    ['blocking'])