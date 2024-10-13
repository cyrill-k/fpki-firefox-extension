# fpki-browser-extension
Firefox extension for F-PKI

## Folder Structure
The [app](./app) folder contains the browser extension

The [mapserver](./mapserver) folder contains the HTTP version of the map server and the tools to generate testing RPC and SP

## Test browser extension
First, load the browser extension by visiting `about:debugging` -> `This Firefox`, and then clicking `Load Temporary add-on...` and select the `manifest.json` file in the `app` folder. To test whether the extension works as expected, you can visit the following test urls for both the legacy mode and the policy mode:

- Legacy mode warning: https://legacy-warn.fpki.netsec.ethz.ch
- Legacy mode valid: https://legacy-valid.fpki.netsec.ethz.ch
- Policy mode valid: https://policy-valid.fpki.netsec.ethz.ch
- Policy mode block (issuer): https://policy-wrong-issuer.fpki.netsec.ethz.ch
- Policy mode block (subdomains): https://policy-wrong-domain.fpki.netsec.ethz.ch

## Installation

1. Install dependencies for python (python3 is recommended). From the root folder run:
`cd native-messaging-app`
`pip install -r requirements.txt`
2. Based on your OS in the root folder run:
	- For Windows: `./install-extension.bat`
	- For Linux/MacOS: `./install-extension.sh`

## How to run
There are two ways to try out the extension: a quick and easy setup using an existing map server and a more involved setup including locally running your own map server.

### Quick Setup (no map server)
For this setup, you can simply clone this repository and load the browser extension in your firefox browser.
To load the extension, you have to visit `about:debugging`, click `Load Temporary Add-on...`, and open the file `app/manifest.json`.
Then you're ready to go.

After visiting a website, you can display extension-related information by clicking on the extension icon on the top right and choosing `LF-PKI Browser Extension` or simply using the shortcut `Alt-Shift-J`.
This will show you the validation results, the configuration, and an option to download a log of the extension's operations.

### Involved Setup (including running the map server locally)
Instead of using an existing map server, you can set up your own map server and add arbitrary certificates and policies.

#### Demo Setup
![Alt text](images/overview.png?raw=true"Overview")
The map server will run as a local server, and communicate with the extension via HTTP. During the TLS connection, the extension will query the map server and stop the connection if any malicious behavior is found.

#### Prerequisites
- go version 1.19.2
- mysql 8.0.31 with access for 'root' with password 'root' (only if a native, i.e., non-docker db should be used)
- docker and docker-compose (only if a docker db should be used)

#### Docker setup
- Instruct all commands to use port number 3307 to interact with the docker mysql instance by setting some environment variables: ``. env.bash``
- First, you start up the mysql database in a docker instance: ``docker-compose up``

#### DB setup
- ``cd mapserver``
- ``go mod tidy``
- ``cd ../db``
- ``make initialize``
- The DB should then be accessible via (replace 3307 with 3306 if a non-docker installation is used):
  - mysql -h localhost -P 3307 --protocol TCP -u root -proot
  - mysql -h localhost -P 3307 --protocol TCP -u test -pzaphod

#### Generate test policies along with all necessary certificates
- ``cd ../mapserver``
- ``make generate_test_certs_and_RPC_SP``

#### Add additional certificates
- Put additional certificate that should be used for legacy validation under ``./mapserver/testdata/additional_certs/certs.csv`` with the following format:
  - Row 1 (cert): PEM-encoded leaf certificate
  - Row 2 (chain): list of PEM-encoded intermediate and root certificates forming a chain. First entry is the certificate that issued the leaf certificate, last entry is the root certificate.

#### Run mapserver
- ``go run mapserver.go``

#### If mysql root access is lost
- ``create user root@localhost identified by '';``

#### Add local mapserver to browser extension config file
To fetch mapserver proofs from the local mapserver, you have to add it in the [config file](app/js_lib/config.js):
- uncomment the following line: `{"identity": "local-mapserver", "domain": "http://localhost:8080", "querytype": "lfpki-http-get"},`
- change the following two config values from 1 to 2:
  - `c.set("mapserver-quorum", 2);`
  - `c.set("mapserver-instances-queried", 2);`

Note that you can also **only** use the local mapserver (and ignore the mapserver running at ETH) by uncommenting the line with `ETH-mapserver-top-100k` and setting the values `mapserver-quorum` and `mapserver-instances-queried` to 1.

#### New Structure Idea
- store per-(P)CA cache on the golang side:
  - Domain -> (P)CA -> [
      ts,
      missingCerts,
      ]
  - verify(X) returns:
    - success (policy and/or legacy validation succeeded)
    - need more map server responses:
      - need N responses from the K policy map servers (M0, M1, ..., MK)
      - need N' responses from the K' legacy map servers (M0, M1, ..., MK')
