import {getUrlParameter} from "../../js_lib/helper.js"

// allow popup script to fetch document url of the blocked webpage
browser.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (msg.request === 'get_dom_url') {
        return Promise.resolve({domUrl: getUrlParameter("url")});
    }
});

const fillIn = new Map();
fillIn.set("errorShortDescErrorMessage", "reason");
fillIn.set("errorShortDescDomain", "domain");

fillIn.forEach((param, id) => {
    var reasonElement = document.getElementById(id);
    reasonElement.innerHTML = getUrlParameter(param);
});
