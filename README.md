# fpki-browser-extension
Firefox extension for F-PKI

## Folder Structure
The app folder contains the browser extension

The mapserver folder contains the HTTP version of the map server and the tools to generate testing RPC and SP

## Demo Setup
![Alt text](images/overview.png?raw=true"Overview")
The map server will run as a local server, and communicate with the extension via HTTP. During the TLS connection, the extension will query the map server and stop the connection if any malicious behavior is found.

## How to run
First, you need to set up the map server. 

To setup the database:
``cd tools
.//create_schema.sh``

Then go to mapserver folder
``make generate_test_certs_and_RPC_SP``

And run map server
``go run mapserver.go``

After the map server is set up, load the browser extension. And you can visit the following url:

"https://amazon.com "
"https://pay.amazon.com "
"https://baidu.com "
"https://sellercentral.amazon.com "