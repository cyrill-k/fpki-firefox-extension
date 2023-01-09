const fillIn = new Map();
fillIn.set("errorShortDescErrorMessage", "reason");
fillIn.set("errorShortDescDomain", "domain");

fillIn.forEach((param, id) => {
    var reasonElement = document.getElementById(id);

    const queryString = window.location.search;

    const urlParams = new URLSearchParams(queryString);

    const pContent = urlParams.get(param);

    reasonElement.innerHTML = pContent;
});
