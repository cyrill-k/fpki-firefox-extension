import {getSubject} from "../js_lib/x509utils.js"
import {AllPolicyAttributes, PolicyAttributeToJsonKeyDict, getPolicyChainDescriptors} from "../js_lib/validation-types.js"

var validationResults = null;
var synchronizedConfig = null;
var port = browser.runtime.connect({
    name: "popup to background communication"
});

document.addEventListener('DOMContentLoaded', function() {
    try {
        getElement('openConfigWindow').addEventListener('click', function() {
            port.postMessage("openConfigWindow");
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

function addCollapsibleButton(id, text, decision) {
    let cAttr = "collapsible";
    if (decision === "indefinitive") {
        cAttr += " validation-indefinitive";
    } else if (decision === "block") {
        cAttr += " validation-failure";
    } else if (decision === "warn") {
        cAttr += " validation-warning";
    } else {
        cAttr += " validation-success";
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

async function removeCurrentResult() {
    // remove all div elements inside "validation-results"
    document.querySelector("div#validation-results").innerHTML = "";
}

async function updateValidationResult() {
    // remove existing validation results
    removeCurrentResult();

    if (validationResults === null) {
        getElement("legacy-connection-title").innerHTML = "No connection initiated yet";
        getElement("validation").style.visibility = "visible";
        return;
    }

    // get current tab
    const tabId = (await browser.tabs.query({currentWindow: true, active: true}))[0].id;
    // get current DOM url
    const {domUrl} = await browser.tabs.sendMessage(tabId, {request: 'get_dom_url'});
    const validationResult = validationResults.get(tabId).get(domUrl);

    // get last result for each domain/mapserver
    const lastIndexMap = new Map();
    validationResult.forEach((td, index) => {
        lastIndexMap.set(JSON.stringify({domain: td.domain}), index);
    });

    const recentTrustDecisions = Array.from(lastIndexMap.values()).map(index => validationResult[index]);

    // show the entries in reverse order such that more recently added entries appear on top
    let currentElement = createElementIn("p", {"id": "validation-title"}, "Validation Results", "validation-results");
    recentTrustDecisions.toReversed().forEach((td, index) => {
        if (td.type === "legacy") {
            currentElement = addLegacyValidationResult(td, currentElement, index);
        } else {
            currentElement = addPolicyValidationResult(td, currentElement, index);
        }
    });

    // hide other divs
    getElement("validation").style.visibility = "visible";

    // TODO(cyrill) not sure if this is necessary
    validationResults = null;
}

function addPolicyValidationResult(trustDecision, predecessor, index) {
    if (trustDecision.type !== "policy") {
        return predecessor;
    }

    // create the various container elements
    const div = createElementAfter("div", {"id": "policy-validation-result-"+index, "class": "content"}, "", predecessor);
    const connTitle = createElementIn("p", {"id": "policy-connection-title-"+index}, "Your Connection ("+trustDecision.domain+")", div);
    const connTable = createElementAfter("table", {"id": "policy-connection-certs-"+index}, "", connTitle);

    // fill in information about the current TLS connection
    let table = "<tr><th>Certificates of this connection</th></tr>";
    table += "<tr><td>"+getSubject(trustDecision.connectionCertificateChain[trustDecision.connectionCertificateChain.length - 1])
    table += "</td></tr>";
    trustDecision.connectionCertificateChain.toReversed().slice(1).forEach(c => {
        table += "<tr><td>"+getSubject(c)+"</td></tr>";
    });
    connTable.innerHTML = table;

    // fill in information about conflicts if any conflicts exist
    let finalDecision;
    let confTitle;
    if (trustDecision.policyChain.length === 0) {
        finalDecision = "indefinitive";
        confTitle = createElementAfter("p", {"id": "policy-conflicts-title-"+index, "class": "validation-indefinitive"}, "No Policies for "+trustDecision.domain+" reported", connTable);
    } else {
        // show positive and negative policy evaluations
        if (trustDecision.evaluationResult === 1) {
            finalDecision = "allow";
            confTitle = createElementAfter("p", {"id": "policy-conflicts-title-"+index, "class": "validation-success"}, "No Conflicting Policies for "+trustDecision.domain+" reported", connTable);
        } else {
            finalDecision = "block";
            confTitle = createElementAfter("p", {"id": "policy-conflicts-title-"+index, "class": "validation-failure"}, "Conflicting Policies for "+trustDecision.domain+" reported", connTable);
        }

        // create table with relevant policy certificate chain
        const policyCertTable = createElementAfter("table", {"id": "policy-certificate-"+index}, "", confTitle);
        table = "<tr><th colspan=\"2\">Policy Certificate Chain</th></tr>";
        table += "<tr><th>Type</th><th>Attributes</th></tr>";
        const policyChainDescriptors = getPolicyChainDescriptors(trustDecision.policyChain);
        for (let index = policyChainDescriptors.length-1; index >= 0; index--) {
            const desc = policyChainDescriptors[index];
            const p = JSON.parse(trustDecision.policyChain[index]).O;
            let attributes = "-";
            if (Object.keys(p.PolicyAttributes).length > 0) {
                attributes = JSON.stringify(p.PolicyAttributes);
            }
            table += "<tr><td>"+desc+"</td><td>"+attributes+"</td></tr>";
        }
        policyCertTable.innerHTML = table;

        // create table with conflicting policy attributes in this policy chain
        if (trustDecision.conflictingPolicies.length > 0) {
            table = "<tr><th colspan=\"3\">Applicable Policy</th><th colspan=\"" + AllPolicyAttributes.length + "\">Evaluation Result</th></tr>";
            table += "<tr><th>Policy Certificate</th><th>Domain</th><th>Relevant Attributes</th>";
            table += AllPolicyAttributes.map(a => "<th>" + a + "</th>");
            table += "</tr>";
            const confTable = createElementAfter("table", { "id": "policy-conflicts-certs-" + index }, "", policyCertTable);
            trustDecision.conflictingPolicies.forEach((polJson, index) => {
                const pol = JSON.parse(polJson);
                table += "<tr>";
                table += "<td>" + policyChainDescriptors[index] + "</td>"
                table += "<td>" + pol.Domain + "</td>"
                table += "<td>" + JSON.stringify(pol.Attribute) + "</td>"
                table += AllPolicyAttributes.map(attribute => {
                    const hasAttribute = PolicyAttributeToJsonKeyDict[attribute] in pol.Attribute;
                    let content;
                    if (!hasAttribute) {
                        content = "-";
                    } else {
                        if (trustDecision.evaluationResult === 1) {
                            content = "<p class=\"validation-success\">Validation Passed</p>";
                        } else {
                            content = "<p class=\"validation-failure\">Validation Failed</p>";
                        }
                    }
                    return "<td>" + content + "</td>";
                });
                table += "</tr>"
            });
            confTable.innerHTML = table;
        }
    }

    // add button to collapse a section (all sessions are initially collapsed)
    addCollapsibleButton("policy-validation-result-"+index, "Policy Validation ("+trustDecision.domain+") reported", finalDecision);

    return div;
}

function addLegacyValidationResult(trustDecision, predecessor, index) {
    if (trustDecision.type !== "legacy") {
        return predecessor;
    }

    // create the various container elements
    const div = createElementAfter("div", {"id": "legacy-validation-result-"+index, "class": "content"}, "", predecessor);
    const connTitle = createElementIn("p", {"id": "legacy-connection-title-"+index}, "Your Connection ("+trustDecision.domain+")", div);
    const connTable = createElementAfter("table", {"id": "legacy-connection-certs-"+index}, "", connTitle);

    // fill in information about the current TLS connection
    let table = "<tr><th colspan=\"2\">Connection Certificate ("
    table += "trust level = "+trustDecision.connectionTrustLevel;
    if (trustDecision.connectionTrustLevelCASet === "DEFAULT") {
        table += " [default] ";
    }
    table += ")</th></tr>";
    table += "<tr><th>Type</th><th>Subject</th><tr>";
    trustDecision.connectionCertificateChain.toReversed().forEach((c, index) => {
        table += "<tr><td>"
        if (index === 0) {
            table += "Root";
        } else if (index < trustDecision.connectionCertificateChain.length-1) {
            table += "Intermediate";
        } else {
            table += "Leaf";
        }
        table += "</td><td>"+getSubject(c)+"</td></tr>";
    });
    connTable.innerHTML = table;


    // fill in information about conflicts if any conflicts exist
    let confTitle;
    if (trustDecision.evaluationResult === 1) {
        confTitle = createElementAfter("p", {"id": "legacy-conflicts-title-"+index, "class": "validation-success"}, "No Conflicting Certificates for "+trustDecision.domain+" reported", connTable);
    } else {
        confTitle = createElementAfter("p", {"id": "legacy-conflicts-title-"+index, "class": "validation-warning"}, "Conflicting Certificates for "+trustDecision.domain+" reported", connTable);
        table = "<tr><th colspan=\"3\">Conflicting Certificates (trust level "+trustDecision.highestTrustLevel+")</th></tr>";
        table += "<tr><th colspan=\"2\">CA Certificate</th><th>Leaf Certificate</th></tr>";
        table += "<tr><th>CA Set</th><th>Subject</th><th>Subject</th></tr>";
        const confTable = createElementAfter("table", {"id": "legacy-conflicts-certs-"+index}, "", confTitle);
        trustDecision.highestTrustLevelCASets.forEach((caSetID, index) => {
            table += "<tr>";
            table += "<td>"+caSetID+"</td>";
            table +="<td>"+trustDecision.highestTrustLevelChainSubjects[index][trustDecision.highestTrustLevelChainIndices[index]]+"</td>";
            table +="<td>"+trustDecision.highestTrustLevelChainSubjects[index][0]+"</td>";
            table += "</tr>"
        });
        confTable.innerHTML = table;
    }

    // add button to collapse a section (all sessions are initially collapsed)
    addCollapsibleButton("legacy-validation-result-"+index, "Legacy Validation ("+trustDecision.domain+") reported", trustDecision.evaluationResult === 0 ? "warn" : "allow");

    return div;
}

// communication from background script to popup
port.onMessage.addListener(async function(msg) {
    const {msgType, value, config} = msg;
    if (msgType === "validationResults") {
        validationResults = value;

        // config is necessary to enable/disable web assembly support
        synchronizedConfig = config;
        window.GOCACHE = config.get("wasm-certificate-parsing");

        await updateValidationResult();
    }
    console.log("message received: " + JSON.stringify(msg));
});
