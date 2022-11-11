import {errorTypes, FpkiError} from "./errors.js"
import {queryMapServerHttp, extractPolicy} from "./LF-PKI-accessor.js"
import {mapGetList} from "./helper.js"
import {config} from "./config.js"

var fpkiRequests = new Map();

var pcaPoliciesCache = new Map();

export class FpkiRequest {
    constructor(mapserver, domain) {
        this.mapserver = mapserver;
        this.domain = domain;
        this.requestInitiated = new Date();
    }

    initiateFetchingPoliciesIfNecessary() {
        this.policiesPromise = this.#initiateFetchPolicies(config.get("max-connection-setup-time"));
        return this.policiesPromise;
    }

    fetchPolicies() {
        this.policiesPromise = this.#initiateFetchPolicies();
        return this.policiesPromise;
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
            console.log("using cached entry ["+this.domain+", "+this.mapserver.identity+"]");
            return getLatestPcaPolicies(this.domain).get(this.mapserver).pcaPolicies;
        } else if (activeRequest !== null) {
            console.log("reusing existing active request ["+this.domain+", "+this.mapserver.identity+"]");
            return activeRequest.policiesPromise;
        } else {
            console.log("create new fetching request ["+this.domain+", "+this.mapserver.identity+"]");

            // add this request to ensure that no other request is scheduled for the same domain
            fpkiRequests.set(this.domain, mapGetList(fpkiRequests, this.domain).concat(this));

            let mapResponse;
            // fetch policy for the mapserver over the configured channel (e.g., http get)
            switch (this.mapserver.querytype) {
            case "lfpki-http-get":
                mapResponse = await queryMapServerHttp(this.mapserver.domain, this.domain);
                break;
            default:
                throw new FpkiError(errorTypes.INVALID_CONFIG, "Invalid mapserver config: "+this.mapserver.querytype)
                break;
            }

            // extract policies from payload
            const policies = extractPolicy(mapResponse);

            // add policies to policy cache
            addPcaPolicies(this.requestInitiated, this.domain, this.mapserver, policies);

            // now that the request is finished and the result is cached, the request can be removed from the list of active requests
            fpkiRequests.delete(this.domain);

            return policies;
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
