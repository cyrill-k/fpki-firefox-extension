function normalise(url) {
    const uri = new URL(url)

    // Normalise hosts with tailing dots, e.g. "www.example.com."
    while (uri.hostname[uri.hostname.length - 1] === '.' && uri.hostname !== '.') {
        uri.hostname = uri.hostname.slice(0, -1)
    }

    if(uri.hostname.startsWith("www.")){
        uri.hostname = uri.hostname.slice(4)
    }

    return uri
}

async function getDomainNameFromURL(url) {
    let domainName = normalise(url).hostname
    return domainName
}

function getParentDomain(domainName){
    const after = domainName.slice(domainName.indexOf('.') + 1)
    return after
}

export {
    getDomainNameFromURL,
    getParentDomain
  }
