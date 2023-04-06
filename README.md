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

### Prerequisites
- go version 1.19.2
- mysql 8.0.31 with access for 'root' with password 'root' (only if a native, i.e., non-docker db should be used)
- docker and docker-compose (only if a docker db should be used)

### Docker setup
- Instruct all commands to use port number 3307 to interact with the docker mysql instance by setting some environment variables: ``. env.bash``
- First, you start up the mysql database in a docker instance: ``docker-compose up``

### DB setup
- ``cd mapserver``
- ``go mod tidy``
- ``cd ../db``
- ``make initialize``
- The DB should then be accessible via (replace 3307 with 3306 if a non-docker installation is used):
  - mysql -h localhost -P 3307 --protocol TCP -u root -proot
  - mysql -h localhost -P 3307 --protocol TCP -u test -pzaphod

### Generate test policies along with all necessary certificates
- ``cd ../mapserver``
- ``make generate_test_certs_and_RPC_SP``

### Add additional certificates
- Put additional certificate that should be used for legacy validation under ``./mapserver/testdata/additional_certs/certs.csv`` with the following format:
  - Row 1 (cert): PEM-encoded leaf certificate
  - Row 2 (chain): list of PEM-encoded intermediate and root certificates forming a chain. First entry is the certificate that issued the leaf certificate, last entry is the root certificate.

### Run mapserver
- ``go run mapserver.go``

### If mysql root access is lost
- ``create user root@localhost identified by '';``

### Test browser extension
After the map server is set up, load the browser extension by visiting ``about:debugging``. And you can visit the following urls to test whether it correctly works:

- Legacy allow: https://bing.com
- Legacy block: https://microsoft.com
- Policy (issuer) allow: https://m.media-amazon.com/images/G/01/AmazonStores/Help/assets/img/gallery-img1.png
- Policy (issuer) block: https://baidu.com
- Policy (subcomains) allow: https://netsec.ethz.ch
- Policy (subcomains) block: https://sellercentral.amazon.com
