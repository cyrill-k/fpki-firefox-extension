function normalise(url) {
    const uri = new URL(url)

    // Normalise hosts with tailing dots, e.g. "www.example.com."
    while (uri.hostname[uri.hostname.length - 1] === '.' && uri.hostname !== '.') {
        uri.hostname = uri.hostname.slice(0, -1)
    }

    return uri
}

function getDomainNameFromURL(url) {
    return normalise(url).hostname
}

export {
    getDomainNameFromURL
  };
