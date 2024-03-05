/**
 * Removes trailing dots and `www` prefix from urls hostname
 *
 * @param {String} url 
 * @returns {String} normalized url
 */
function normalise(url) {
    const uri = new URL(url)

    // Normalise hosts with tailing dots, e.g. "www.example.com."
    while (uri.hostname[uri.hostname.length - 1] === '.' && uri.hostname !== '.') {
        uri.hostname = uri.hostname.slice(0, -1)
    }

    if (uri.hostname.startsWith("www.")) {
        uri.hostname = uri.hostname.slice(4)
    }

    return uri
}


/**
 * Returns the hostname of the normalised url.
 *
 * @param {string} url
 */
function getDomainNameFromURL(url) {
    let domainName = normalise(url).hostname
    return domainName
}


/**
 * Expects domain name and removes first subdomain part, e.g.
 * `mail.google.com` becomes `google.com`.
 *
 * @param {string} domainName 
 */
function getParentDomain(domainName) {
    const parentDomain = domainName.slice(domainName.indexOf('.') + 1)
    return parentDomain
}

/**
 * Returns true if the domain is a TLD. Note that this function also considers "*" a TLD (i.e., single label without dot)
 *
 * @param {string} domainName
 */
function isTopLevelDomain(domainName) {
    return domainName.endsWith(".") ? !domainName.substring(0, domainName.length-1).includes(".") : !domainName.includes(".")
}

/**
 * Returns the wildcard domain corresponding to the given domain.
 *
 * @param {string} domainName
 */
function getWildcardDomain(domainName) {
    return isTopLevelDomain(domainName) ? "*" : `*.${getParentDomain(domainName)}`;
}

export {
    getDomainNameFromURL,
    getParentDomain,
    isTopLevelDomain,
    getWildcardDomain,
  }
