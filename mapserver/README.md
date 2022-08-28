#Http Version of Map Server
This folder contains the http version of map server, and the necessary tools for the test.

##Folder Structure
certs folder contains all the pseudo certificates for map server and PCA

rpc_and_sp folder contains all the pseudo RPC and SP for the demo

tools folder contains the tools to generate testing RPC and SP for testing. For example, issuance, logging and verification of RPC and SP.

##Generate test certs, RPC and SP
To generate the test certs, RPC and SP, run:
```
make generate_test_certs_and_RPC_SP
```