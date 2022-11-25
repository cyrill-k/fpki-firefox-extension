import {errorTypes, FpkiError} from "./errors.js"
import {queryMapServerHttp, extractPolicy} from "./LF-PKI-accessor.js"
import {mapGetList, cLog, printMap} from "./helper.js"
import {config} from "./config.js"

var fpkiRequests = new Map();

var pcaPoliciesCache = new Map();

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
            cLog(this.requestId, "removed request: "+JSON.stringify(this));
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
        const cachedValidEntries = !shouldFetchPcaPoliciesForMapserver(this.domain, this.mapserver, maxTimeToExpiration);
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
            const {pcaPolicies, timestamp} = getLatestPcaPolicies(this.domain).get(this.mapserver);
            const metrics = {type: "cached", lifetime: timestamp-new Date()+config.get("cache-timeout")};
            return {policies: pcaPolicies, metrics};
        } else if (activeRequest !== null) {
            cLog(this.requestId, "reusing existing active request ["+this.domain+", "+this.mapserver.identity+"]: "+activeRequest.requestId);
            cLog(this.requestId, printMap(fpkiRequests));
            const startTime = performance.now();
            let {policies, metrics} = await activeRequest.policiesPromise;
            if (this.requestId !== activeRequest.requestId) {
                const endTime = performance.now();
                metrics = {...metrics, type: "ongoing-request", initiatedOffset: new Date()-activeRequest.requestInitiated}
            }
            return {policies, metrics};
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

                // extract metrics from performance resource entry
                const {duration, transferSize, connectStart, connectEnd, secureConnectionStart} = performanceResourceEntry;
                // measure RTT by calculating the SYN-ACK handshake duration
                const mapserverRtt = secureConnectionStart === 0 ? connectEnd-connectStart : secureConnectionStart-connectStart;
                const metrics = {duration, size: transferSize, rtt: mapserverRtt, initiated: this.requestInitiated, type: "fetch", nRetries};

                // extract policies from payload
                const policies = extractPolicy(mapResponse);
                cLog(this.requestId, "fetch finished for: "+this);

                // add policies to policy cache
                addPcaPolicies(this.requestInitiated, this.domain, this.mapserver, policies);

                return {policies, metrics};
            } catch (error) {
                throw error;
            } finally {
                this.removeFromActiveRequestsIfPossible();
            }
        }
    }
};

class PcaPoliciesCacheEntry {
    constructor(timestamp, mapserver, pcaPolicies) {
        this.timestamp = timestamp;
        this.mapserver = mapserver;
        this.pcaPolicies = pcaPolicies;
    }
}

function addPcaPolicies(timestamp, domain, mapserver, pcaPolicies) {
    const cacheEntry = new PcaPoliciesCacheEntry(timestamp, mapserver, pcaPolicies);
    pcaPoliciesCache.set(domain, mapGetList(pcaPoliciesCache, domain).concat(cacheEntry));
}

function getLatestPcaPolicies(domain) {
    const latestPolicies = new Map();
    if (pcaPoliciesCache.has(domain)) {
        for (const cacheEntry of pcaPoliciesCache.get(domain)) {
            const {timestamp, mapserver} = cacheEntry;
            // TODO: see if this really works of if we need some kind of mapserver identity
            if (!latestPolicies.has(mapserver) || timestamp > latestPolicies.get(mapserver).timestamp) {
                latestPolicies.set(mapserver, cacheEntry);
            }
        }
    }
    return latestPolicies;
}

function shouldFetchPcaPoliciesForMapserver(domain, mapserver, maxTimeToExpiration=0) {
    return getValidPcaPoliciesForMapserver(domain, mapserver, maxTimeToExpiration).length === 0;
}

function getValidPcaPoliciesForMapserver(domain, mapserver, maxTimeToExpiration=0) {
    return getAllValidPcaPolicies(domain, maxTimeToExpiration).
        filter(
            ({mapserver: entryMapserver}) => entryMapserver === mapserver
        );
}

function getAllValidPcaPolicies(domain, maxTimeToExpiration=0) {
    const currentTime = new Date();
    const validPcaPolicies = [];
    getLatestPcaPolicies(domain).forEach(function(cacheEntry, mapserver) {
        const {timestamp, pcaPolicies} = cacheEntry;
        if (currentTime-timestamp < config.get("cache-timeout")-maxTimeToExpiration) {
            validPcaPolicies.push(cacheEntry);
        }
    });
    return validPcaPolicies;
}
