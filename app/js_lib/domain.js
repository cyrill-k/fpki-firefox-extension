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
function getParentDomain(domainName){
    const parentDomain = domainName.slice(domainName.indexOf('.') + 1)
    return parentDomain
}


export {
    getDomainNameFromURL,
    getParentDomain
  }
