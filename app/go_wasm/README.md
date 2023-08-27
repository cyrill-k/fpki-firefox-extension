
## Enabling the Go cache
Adjust the following two configurations in `../js_lib/config.js`:
- set `wasm-certificate-parsing` to `false`
- set `wasm-certificate-caching` to `true`

## Interface
The `cache_v2/` directory contains the Go implementation of the certificate cache (`cache_v2/cache.go`),
the legacy validation (`cache_v2/validation.go`) and some utility functionality that can be used to integrate the 
proof validation (`cache_v2/proofs.go`).

The `main.go` file contains the implementation of the middleware functionality
between Go and JS. 
The `main()` function defines the following interface for calling the Go functions
from JS:
* `initializeGoDatastructures(trustStoreDir string, configFilePath string)`: This function initializes
the certificate cache  with the PEM encoded root certificates located in 
`trustStoreDir` and reads in the legacy trust preferences from the config file 
located at `configFilePath` on the Go side.
**NOTE: these files must be located within the `cache_v2/embedded/` directory.**
* `getMissingCertificatesList(certificateHashes Uint8Array, certificateHashesLength int)`: This function 
takes a list of base64 encoded certificate hashes (JSON encoded as Uint8Array) and returns a list 
containing exactly the certificate hashes that are not yet cached. 
`certificateHashLength` contains the length of `certificateHashes` in bytes. 
* `addCertificatesToCache(certificates Uint8Array, certificatesLength int)`: This function
takes a list of base64 encoded certificates (PEM without header/footer) (JSON encoded as Uint8Array) and adds the 
certificates to the certificate cache. `certificatesLength` contains the length of 
`certificates` in bytes.
* `verifyLegacy(dnsName string, connectionChain Uint8Array, connectionChainLength int)`: This function takes 
the domain name to which the client wants to connect to and the certificate chain received in the TLS handshake
  (encoded equivalently to `addCertificatesChain`)  
and returns a `LegacyTrustDecisionGo` object (a JS object).
This object contains the result of the legacy validation and additional information
in case of a negative validation result and gets cached on the JS side.

The functions called `...Wrapper()` (e.g., `addCertificatesToCacheWrapper()`) are 
the functions that get executed when one of the above functions are called from JS
(they are bound to each other in the `main()` function).
These functions encode and decode the data between Go and JS and call the 
appropriate Go function.
(e.g., `addCertificatesToCacheWrapper()` takes as input a byte array representing a JSON object and parses it
to a slice of `x509.Certificate`, before passing them to 
`cache_v2.AddCertificatesToCache(certificates []*x509.Certificate)`).

## Compiling Go to WASM

**IMPORTANT: in order for the compilation to produce a valid `WASM` file, it is 
crucial that `main.go` is declared to be part of the `main` package**

1. If you want to use a custom trust store, replace the certificates inside `cache_v2/embedded/ca-certificates` with your custom root trust certificates
2. Add your config file containing your legacy trust preferences to `cache_v2/embedded/`
3. Add the X.509 wrapper `x509_extensions/wrappers.go` to your local Go source
4. (probably `usr/local/go/src/crypto/x509/`)
5. Inside the current directory, execute `GOOS=js GOARCH=wasm go build -o cache_v2.wasm` to create
a WASM file called `cachev2.wasm`

## Integrating WASM in JS /as done in `../background/background.js`
1. import [wasm_exec.js](https://github.com/golang/go/blob/master/misc/wasm/wasm_exec.js) file:
`import wasm_exec.js`
2. Instantiate and initialize the WASM backend
```javascript
const go = new Go();
WebAssembly. instantiateStreaming (fetch("../app/go_wasm/cachev2.wasm"), go. importObject)
.then (( result) => {
go.run(result.instance);
initializeGODatastructures([path_to_trust_store_dir], [path_to_config]);
});
```

Now you can call WASM functions from JS using the above interface.

**IMPORTANT NOTE: As most certificates stored at the map server are currently expired, we manually adjust the certificate validity period (NotAfter) to 2023-08-30 (LOC 164 in `../main.go`).For further testing of the browser extension, this validity period must be adjusted. For an actual release, the certificates at the map server should be reloaded and the manual adjustments MUST be deleted.**