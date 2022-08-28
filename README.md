# fpki-browser-extension
Google chrome extension for F-PKI

## Folder Structure
The app folder contains the browser extension (not developed yet)

The mapserver folder contains the HTTP version of the map server and the tools to generate testing RPC and SP

## Demo Setup
![Alt text](images/overview.png?raw=true"Overview")
The map server will run as a local server, and communicate with the extension via HTTP. During the TLS connection, the extension will query the map server and throw a warning if any malicious behavior is found.