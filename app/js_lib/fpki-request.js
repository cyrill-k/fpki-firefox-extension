import {errorTypes, FpkiError} from "./errors.js"
import {queryMapServerHttp, extractPolicy, extractCertificates} from "./LF-PKI-accessor.js"
import {mapGetList, cLog, printMap} from "./helper.js"
import {config} from "./config.js"

var fpkiRequests = new Map();

var mapserverResponseCache = new Map();

export class FpkiRequest {
    constructor(mapserver, domain, requestId) {
        this.mapserver = mapserver;
        this.domain = domain;
        this.requestInitiated = new Date();
        this.requestId = requestId;
    }

    initiateFetchingPoliciesIfNecessary() {
        this.policiesPromise = this.#initiateFetchPolicies(config.get("max-connection-setup-time"));
        // const promise = this.policiesPromise;
        // this.wrappedPoliciesPromise = (async () => {
            // return await promise;
        // })();
        // return this.wrappedPoliciesPromise;
        return this.policiesPromise;
    }

    fetchPolicies() {
        this.policiesPromise = this.#initiateFetchPolicies();
        // const promise = this.policiesPromise;
        // this.wrappedPoliciesPromise = (async () => {
            // return await promise;
        // })();
        // return this.wrappedPoliciesPromise;
        return this.policiesPromise;
    }

    // removes the request for this domain and mapserver from the list of active requests
    // returns true if a request was removed and false otherwise
    removeFromActiveRequestsIfPossible() {
        const currentRequests = fpkiRequests.get(this.domain);
        const mapserver = this.mapserver
        const index = currentRequests.findIndex(request=>request.mapserver===mapserver);
        if (index !== -1) {
            currentRequests.splice(index, 1);
            fpkiRequests.set(this.domain, currentRequests);
            // cLog(this.requestId, "removed request: "+JSON.stringify(this));
            return true;
        }
        cLog(this.requestId, "couldn't find request");
        return false;
    }

    #getLatestPerformanceResourceEntry(fetchUrl) {
        return performance.getEntriesByName(fetchUrl, "resource").reduce(
            (prev, current) =>
            prev === null || prev.startTime < current.startTime ? current : prev,
            null);
    }

    async #initiateFetchPolicies(maxTimeToExpiration=0) {
        const cachedValidEntries = !shouldFetchMapserverResponseForMapserver(this.domain, this.mapserver, maxTimeToExpiration);
        const mapserver = this.mapserver;
        let activeRequest = null;
        if (fpkiRequests.has(this.domain)) {
            fpkiRequests.get(this.domain).forEach(function(request) {
                if (request.mapserver === mapserver) {
                    activeRequest = request;
                    return false;
                }
            })
        }

        if (cachedValidEntries) {
            cLog(this.requestId, "using cached entry ["+this.domain+", "+this.mapserver.identity+"]");
            const {pcaPolicies, certificates, timestamp} = getLatestMapserverResponse(this.domain).get(this.mapserver);
            const metrics = {type: "cached", lifetime: timestamp-new Date()+config.get("cache-timeout")};
            return {policies: pcaPolicies, certificates, metrics};
        } else if (activeRequest !== null) {
            cLog(this.requestId, "reusing existing active request ["+this.domain+", "+this.mapserver.identity+"]: "+activeRequest.requestId);
            const startTime = performance.now();
            let {policies, certificates, metrics} = await activeRequest.policiesPromise;
            if (this.requestId !== activeRequest.requestId) {
                const endTime = performance.now();
                metrics = {...metrics, type: "ongoing-request", initiatedOffset: new Date()-activeRequest.requestInitiated}
            }
            return {policies, certificates, metrics};
        } else {
            cLog(this.requestId, "create new fetching request ["+this.domain+", "+this.mapserver.identity+"]");

            // add this request to ensure that no other request is scheduled for the same domain
            fpkiRequests.set(this.domain, mapGetList(fpkiRequests, this.domain).concat(this));

            // execute the fetching and response parsing in a try block to ensure that the active request is dropped whether the operations succeed or fail
            try {
                let mapResponse, performanceResourceEntry, nRetries;
                // fetch policy for the mapserver over the configured channel (e.g., http get)
                switch (this.mapserver.querytype) {
                case "lfpki-http-get":
                    const result = await queryMapServerHttp(this.mapserver.domain, this.domain, {timeout: 5000, requestId: this.requestId, maxTries: config.get("max-retries")});
                    mapResponse = result.response;
                    nRetries = result.nRetries;
                    performanceResourceEntry = this.#getLatestPerformanceResourceEntry(result.fetchUrl);
                    break;
                default:
                    throw new FpkiError(errorTypes.INVALID_CONFIG, "Invalid mapserver config: "+this.mapserver.querytype)
                    break;
                }

                let metrics = {};
                if (performanceResourceEntry !== null) {
                    // extract metrics from performance resource entry
                    const {duration, transferSize, connectStart, connectEnd, secureConnectionStart} = performanceResourceEntry;
                    // measure RTT by calculating the SYN-ACK handshake duration
                    const mapserverRtt = secureConnectionStart === 0 ? connectEnd-connectStart : secureConnectionStart-connectStart;
                    metrics = {duration, size: transferSize, rtt: mapserverRtt, initiated: this.requestInitiated, type: "fetch", nRetries};
                } else {
                    console.log(performance.getEntriesByType("resource"));
                    console.log("Too many resource entries. Clearing entries...");
                    performance.clearResourceTimings();
                    // TODO: add "no metric" statement to log entry
                }

                // extract policies from payload
                const policies = extractPolicy(mapResponse);
                const certificates = extractCertificates(mapResponse);
                cLog(this.requestId, "fetch finished for: "+this);

                // add policies to policy cache
                addMapserverResponse(this.requestInitiated, this.domain, this.mapserver, policies, certificates);

                return {policies, certificates, metrics};
            } catch (error) {
                throw error;
            } finally {
                this.removeFromActiveRequestsIfPossible();
            }
        }
    }
};


class MapserverResponseCacheEntry {
    constructor(timestamp, mapserver, pcaPolicies, certificates) {
        this.timestamp = timestamp;
        this.mapserver = mapserver;
        this.pcaPolicies = pcaPolicies;
        this.certificates = certificates;
    }
}

function addMapserverResponse(timestamp, domain, mapserver, pcaPolicies, certificates) {
    const cacheEntry = new MapserverResponseCacheEntry(timestamp, mapserver, pcaPolicies, certificates);
    mapserverResponseCache.set(domain, mapGetList(mapserverResponseCache, domain).concat(cacheEntry));
}

function getLatestMapserverResponse(domain) {
    const latestPolicies = new Map();
    if (mapserverResponseCache.has(domain)) {
        for (const cacheEntry of mapserverResponseCache.get(domain)) {
            const {timestamp, mapserver} = cacheEntry;
            // TODO: see if this really works of if we need some kind of mapserver identity
            if (!latestPolicies.has(mapserver) || timestamp > latestPolicies.get(mapserver).timestamp) {
                latestPolicies.set(mapserver, cacheEntry);
            }
        }
    }
    return latestPolicies;
}

function shouldFetchMapserverResponseForMapserver(domain, mapserver, maxTimeToExpiration=0) {
    return getValidMapserverResponseForMapserver(domain, mapserver, maxTimeToExpiration).length === 0;
}

function getValidMapserverResponseForMapserver(domain, mapserver, maxTimeToExpiration=0) {
    return getAllValidMapserverResponse(domain, maxTimeToExpiration).
        filter(
            ({mapserver: entryMapserver}) => entryMapserver === mapserver
        );
}

function getAllValidMapserverResponse(domain, maxTimeToExpiration=0) {
    const currentTime = new Date();
    const validMapserverResponse = [];
    getLatestMapserverResponse(domain).forEach(function(cacheEntry, mapserver) {
        const {timestamp, pcaPolicies} = cacheEntry;
        if (currentTime-timestamp < config.get("cache-timeout")-maxTimeToExpiration) {
            validMapserverResponse.push(cacheEntry);
        }
    });
    return validMapserverResponse;
}
