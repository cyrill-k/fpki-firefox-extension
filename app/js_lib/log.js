import {printMap} from "./helper.js"

// requestId => LogEntry (mutable)
var ongoingConnectionLogs = new Map();

// finished connection metrics (append-only)
var finishedConnectionLogs = [];

export class LogEntry {
    constructor(createdTimestamp, domain, tabId, method, type, perfStartTimestamp) {
        this.createdTimestamp = createdTimestamp;
        this.domain = domain;
        this.tabId = tabId;
        this.method = method;
        this.type = type;
        this.fpkiRequestInitiateErrors = [];
        this.fpkiResponses = [];
        this.fpkiResponseMetrics = [];
        this.perfStartTimestamp = perfStartTimestamp;
    }

    fpkiRequestInitiateError(mapserver, error) {
        this.fpkiRequestInitiateErrors.push([mapserver, error]);
    }

    fpkiResponse(mapserver, response, metrics) {
        this.fpkiResponses.push([mapserver, Object.fromEntries(response)]);
        this.fpkiResponseMetrics.push([mapserver, metrics]);
    }

    validationFinished(decision, onHeadersReceivedStart, onHeadersReceivedEnd) {
        this.decision = decision;
        this.connectionSetupBase = onHeadersReceivedStart - this.perfStartTimestamp;
        this.connectionSetupOverhead = onHeadersReceivedEnd - onHeadersReceivedStart;
    }

    trackRequest(requestId) {
        ongoingConnectionLogs.set(requestId, this);
    }

    finalizeLogEntry(requestId) {
        finishedConnectionLogs.push(this);
        ongoingConnectionLogs.delete(requestId);
        console.log("finalize log entry");
        console.log(this);
    }
}

export function getLogEntryForRequest(requestId) {
    return ongoingConnectionLogs.get(requestId);
}

function download(filename, text) {
  var element = document.createElement('a');
  element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
  element.setAttribute('download', filename);

  element.style.display = 'none';
  document.body.appendChild(element);

  element.click();

  document.body.removeChild(element);
}

export function printLogEntriesToConsole() {
    console.log("printing log:" + printMap(ongoingConnectionLogs));
    console.log("finalized logs:" + JSON.stringify(finishedConnectionLogs, null, 2));
}

export function downloadLog() {
    download("logs.json", JSON.stringify(finishedConnectionLogs, null, 2));
}
