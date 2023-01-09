var reasonElement = document.getElementById("reason")

const queryString = window.location.search;

const urlParams = new URLSearchParams(queryString);

const reason = urlParams.get('reason')

reasonElement.innerHTML = reason
