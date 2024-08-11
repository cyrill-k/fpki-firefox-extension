var reasonElement = document.getElementById("reason")

const queryString = globalThis.location.search;

const urlParams = new URLSearchParams(queryString);

const reason = urlParams.get('reason')

reasonElement.innerHTML = reason
