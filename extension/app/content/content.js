import { cLog } from "../js_lib/helper";

chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    cLog('content.js', 'chrome.runtime.onMessage.addListener', msg);
    console.log("content.js: chrome.runtime.onMessage.addListener");
    if (msg.request === 'get_dom_url') {
        return Promise.resolve({ domUrl: document.URL });
    }
});
