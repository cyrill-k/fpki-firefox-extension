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
- ``cd tools``
- ``mysql -u root``
- ``USE mysql;``
- ``CREATE USER 'test'@'localhost' IDENTIFIED BY 'zaphod';``
- ``GRANT ALL PRIVILEGES ON *.* TO 'test'@'localhost';``
- ``UPDATE user SET plugin='auth_socket' WHERE User='test';``
- ``FLUSH PRIVILEGES;``
- ``CREATE DATABASE test;``
- ``.//create_schema.sh``

### If mysql root access is lost
- ``create user root@localhost identified by '';``

Then reset the database using the trillian reset script:
- ``export MYSQL_PORT=3307``
- ``export MYSQL_ROOT_USER=root``
- ``export MYSQL_ROOT_PASSWORD=root``
- ``cd /home/<user>/go/pkg/mod/github.com/google/trillian@v1.4.1``
- ``bash ./scripts/resetdb.sh --protocol TCP``

Then go to mapserver folder
- ``make generate_test_certs_and_RPC_SP``

Check out the fpki code (https://github.com/netsec-ethz/fpki) on branch `grpc`
- modify default db config

And run map server
- ``go run mapserver.go``

After the map server is set up, load the browser extension. And you can visit the following url:

"https://amazon.com "
"https://pay.amazon.com "
"https://baidu.com "
"https://sellercentral.amazon.com "

## Try to see what happens if an embedded picture is blocked
https://images-na.ssl-images-amazon.com/images/G/01/AmazonExports/Fuji/2021/June/Fuji_Quad_Headset_1x._SY116_CB667159060_.jpg


## requirements
go version 1.19.2
mysql 8.0.31
mysql -h localhost -P 3307 --protocol TCP -u root -proot
mysql -h localhost -P 3307 --protocol TCP -u test -pzaphod

## new test websites

### policy issuer
https://m.media-amazon.com
https://baidu.com

### policy subdomain
https://netsec.ethz.ch
https://sellercentral.amazon.com

### legacy
https://azure.microsoft.com
https://bing.com
