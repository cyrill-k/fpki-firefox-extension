import {getSubject, getIssuer} from "../js_lib/x509utils.js"
import {AllPolicyAttributes, EvaluationResult} from "../js_lib/validation-types.js"

var synchronizedConfig = null;
var validationResult = null;
var port = browser.runtime.connect({
    name: "popup to background communication"
});
function updateConfig() {
    const configCodeElement = getElement("config-code");
    const printableConfig = new Map();
    synchronizedConfig.forEach((value, key) => {
        if (["ca-sets", "legacy-trust-preference", "policy-trust-preference", "root-pcas", "root-cas"].includes(key)) {
            printableConfig.set(key, Object.fromEntries(value));
        } else {
            printableConfig.set(key, value);
        }
        // could try to implement using the datatype: e.g., if (typeof value === "map")
    });
    configCodeElement.innerHTML = "config = "+JSON.stringify(Object.fromEntries(printableConfig), null, 4);

    // hide other divs
    getElement("config").style.visibility = "visible";
    getElement("validation").style.visibility = "collapsed";
}

document.addEventListener('DOMContentLoaded', function() {
    try {
        getElement('printLog').addEventListener('click', function() {
            port.postMessage("printLog");
            updateConfig();
        });
        getElement('downloadLog').addEventListener('click', function() {
            port.postMessage("downloadLog");
        });
        getElement('showValidationResult').addEventListener('click', function() {
            port.postMessage("showValidationResult");
        });
    } catch (e) {
        console.log("popup button setup: "+e);
    }
    port.postMessage("showValidationResult");

    const coll = document.getElementsByClassName("collapsible");

    for (let i = 0; i < coll.length; i++) {
        coll[i].addEventListener("click", function() {
            this.classList.toggle("active");
            var content = this.nextElementSibling;
            if (content.style.display === "block") {
                content.style.display = "none";
            } else {
                content.style.display = "block";
            }
        });
    }
});

function getElement(nameOrElement) {
    if (typeof nameOrElement === "string") {
        return document.getElementById(nameOrElement);
    } else {
        return nameOrElement;
    }
}

function createElement(name, attributes, content) {
    const e = document.createElement(name);
    e.innerHTML = content;
    new Map(Object.entries(attributes)).forEach((v, k) => {
        const typeAttr = document.createAttribute(k);
        typeAttr.value = v;
        e.setAttributeNode(typeAttr);
    });
    return e;
}

function createElementAfter(name, attributes, content, previousId) {
    const previous = getElement(previousId);
    const parent = previous.parentNode;
    const e = createElement(name, attributes, content);
    parent.insertBefore(e, previous.nextSibling);
    return e;
}

function createElementBefore(name, attributes, content, nextId) {
    const next = getElement(nextId);
    const parent = next.parentNode;
    const e = createElement(name, attributes, content);
    parent.insertBefore(e, next);
    return e;
}

function createElementIn(name, attributes, content, parentId) {
    const parent = getElement(parentId);
    const e = createElement(name, attributes, content);
    parent.appendChild(e);
    return e;
}

function addCollapsibleButton(id, text, isFailure) {
    let cAttr;
    if (isFailure) {
        cAttr = "collapsible validation-failure";
    } else {
        cAttr = "collapsible validation-success";
    }
    const button = createElementBefore("button", {"type": "button", "class":  cAttr}, text, id);
    button.addEventListener("click", function() {
        this.classList.toggle("active");
        var content = this.nextElementSibling;
        if (content.style.display === "block") {
            content.style.display = "none";
        } else {
            content.style.display = "block";
        }
    });
}

function updateValidationResult() {
    if (validationResult === null) {
        getElement("legacy-connection-title").innerHTML = "No connection initiated yet";
        getElement("validation").style.visibility = "visible";
        getElement("config").style.visibility = "visible";
        return;
    }

    // get last result for each domain/mapserver
    const lastIndexMap = new Map();
    validationResult.forEach((td, index) => {
        lastIndexMap.set(JSON.stringify({domain: td.domain, mapserver: td.mapserver.identity}), index);
    });

    const recentTrustDecisions = Array.from(lastIndexMap.values()).map(index => validationResult[index]);

    // show the entries in reverse order such that more recently added entries appear on top
    let currentElement = "validation-title";
    recentTrustDecisions.reverse().forEach((td, index) => {
        if (td.type === "legacy") {
            currentElement = addLegacyValidationResult(td, currentElement, index);
        } else {
            currentElement = addPolicyValidationResult(td, currentElement, index);
        }
    });

    // hide other divs
    getElement("validation").style.visibility = "visible";
    getElement("config").style.visibility = "collapse";

    // TODO(cyrill) not sure if this is necessary
    validationResult = null;
}

function addPolicyValidationResult(trustDecision, predecessor, index) {
    if (trustDecision.type !== "policy") {
        // TODO(cyrill) fix this, we should never reach this point
        return predecessor;
    }

    // create the various container elements
    const div = createElementAfter("div", {"id": "policy-validation-result-"+index, "class": "content"}, "", predecessor);
    const connTitle = createElementIn("p", {"id": "policy-connection-title-"+index}, "Your Connection ("+trustDecision.domain+")", div);
    const connTable = createElementAfter("table", {"id": "policy-connection-certs-"+index}, "", connTitle);

    // fill in information about the current TLS connection
    let table = "<tr><th>Certificates of this connection</th></tr>";
    table += "<tr><td>"+getSubject(trustDecision.connectionCertChain[trustDecision.connectionCertChain.length - 1])
    table += "</td></tr>";
    trustDecision.connectionCertChain.reverse().slice(1).forEach(c => {
        table += "<tr><td>"+getSubject(c)+"</td></tr>";
    });
    table += "<tr><td>"+getSubject(trustDecision.connectionCert)+"</td></tr>";
    connTable.innerHTML = table;

    // fill in information about conflicts if any conflicts exist
    let confTitle;
    if (trustDecision.decision === "positive") {
        confTitle = createElementAfter("p", {"id": "policy-conflicts-title-"+index, "class": "validation-success"}, "No Conflicting Policies for "+trustDecision.domain+" reported by mapserver "+trustDecision.mapserver.identity, connTable);
    } else {
        confTitle = createElementAfter("p", {"id": "policy-conflicts-title-"+index, "class": "validation-failure"}, "Conflicting Policies for "+trustDecision.domain+" reported by mapserver "+trustDecision.mapserver.identity, connTable);
    }
    table = "<tr><th colspan=\"3\">Policy</th><th colspan=\""+AllPolicyAttributes.length+"\">Evaluation Result</th></tr>";
    table += "<tr><th>Issuer (PCA)</th><th>Domain</th><th>Policy</th>";
    table += AllPolicyAttributes.map(a => "<th>"+a+"</th>");
    table += "</tr>";
    const confTable = createElementAfter("table", {"id": "policy-conflicts-certs-"+index}, "", confTitle);
    trustDecision.policyTrustInfos.forEach(ti => {
        table += "<tr>";
        table += "<td>"+ti.pca+"</td>"
        table += "<td>"+ti.policyDomain+"</td>"
        table += "<td>"+JSON.stringify(ti.policyAttributes)+"</td>"
        table += AllPolicyAttributes.map(attribute => {
            const evaluation = ti.evaluations.find(e => e.attribute === attribute);
            let content;
            if (evaluation === undefined) {
                content = "-";
            } else if (evaluation.evaluationResult === EvaluationResult.SUCCESS) {
                content = "<p class=\"validation-success\">Validation Passed</p>";
            } else if (evaluation.evaluationResult === EvaluationResult.FAILURE) {
                content = "<p class=\"validation-failure\">Validation Failed</p>";
            }
            return "<td>"+content+"</td>";
        });
        table += "</tr>"
    });
    confTable.innerHTML = table;

    // add button to collapse a section (all sessions are initially collapsed)
    addCollapsibleButton("policy-validation-result-"+index, "Policy Validation ("+trustDecision.domain+") reported by "+trustDecision.mapserver.identity, trustDecision.decision === "negative");

    return div;
}

function addLegacyValidationResult(trustDecision, predecessor, index) {
    if (trustDecision.type !== "legacy") {
        // TODO(cyrill) fix this, we should never reach this point
        return predecessor;
    }

    // create the various container elements
    const div = createElementAfter("div", {"id": "legacy-validation-result-"+index, "class": "content"}, "", predecessor);
    const connTitle = createElementIn("p", {"id": "legacy-connection-title-"+index}, "Your Connection ("+trustDecision.domain+")", div);
    const connTable = createElementAfter("table", {"id": "legacy-connection-certs-"+index}, "", connTitle);

    // fill in information about the current TLS connection
    let table = "<tr><th>Certificates of this connection</th></tr>";
    table += "<tr><td>"+getSubject(trustDecision.connectionTrustInfo.certChain[trustDecision.connectionTrustInfo.certChain.length - 1])
    if (trustDecision.connectionTrustInfo.originTrustPreference == null) {
        table += " (trust level = 0, i.e., no trust preference applies to this CA and domain)";
    } else {
        table += " (trust level = "+trustDecision.connectionTrustInfo.rootCaTrustLevel+" from "+JSON.stringify(trustDecision.connectionTrustInfo.originTrustPreference)+")";
    }
    table += "</td></tr>";
    trustDecision.connectionTrustInfo.certChain.reverse().slice(1).forEach(c => {
        table += "<tr><td>"+getSubject(c)+"</td></tr>";
    });
    table += "<tr><td>"+getSubject(trustDecision.connectionTrustInfo.cert)+"</td></tr>";
    connTable.innerHTML = table;

    // fill in information about conflicts if any conflicts exist
    let confTitle;
    if (trustDecision.certificateTrustInfos.length === 0) {
        confTitle = createElementAfter("p", {"id": "legacy-conflicts-title-"+index, "class": "validation-success"}, "No Conflicting Certificates for "+trustDecision.domain+" reported by mapserver "+trustDecision.mapserver.identity, connTable);
    } else {
        confTitle = createElementAfter("p", {"id": "legacy-conflicts-title-"+index, "class": "validation-failure"}, "Conflicting Certificates for "+trustDecision.domain+" reported by mapserver "+trustDecision.mapserver.identity, connTable);
        table = "<tr><th>Root CA</th><th>#Intermediate Certs</th><th>Leaf Certificate</th></tr>";
        const confTable = createElementAfter("table", {"id": "legacy-conflicts-certs-"+index}, "", confTitle);
        trustDecision.certificateTrustInfos.forEach(ti => {
            table += "<tr>";
            if (ti.certChain.length === 0) {
                table += "<td>no certificate chain provided by mapserver (leaf cert issuer: "+getIssuer(ti.cert)+")</td>";
            } else {
                table +="<td>"+getSubject(ti.certChain[ti.certChain.length-1])+" ("+ti.rootCaTrustLevel+" from "+ti.originTrustPreference+")</td>";
            }
            table +="<td>"+ti.certChain.reverse().slice(1).length+"</td>"
            table +="<td>"+getSubject(ti.cert)+"</td>"
            table += "</tr>"
        });
        confTable.innerHTML = table;
    }

    // add button to collapse a section (all sessions are initially collapsed)
    addCollapsibleButton("legacy-validation-result-"+index, "Legacy Validation ("+trustDecision.domain+") reported by "+trustDecision.mapserver.identity, trustDecision.decision === "negative");

    return div;
}

// communication from background script to popup
port.onMessage.addListener(function(msg) {
    const {msgType, value} = msg;
    if (msgType === "config") {
        synchronizedConfig = value;
        updateConfig();
    } else if (msgType === "validationResult") {
        validationResult = value;
        updateValidationResult();
    }
    console.log("message received: " + JSON.stringify(msg));
});
