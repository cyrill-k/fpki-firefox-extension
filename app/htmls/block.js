var reasonElement = document.getElementById("reason")

const queryString = window.location.search;

const urlParams = new URLSearchParams(queryString);

const originalUrl = urlParams.get('original')

const reason = urlParams.get('reason')

console.log(reason)

reasonElement.innerHTML = reason
