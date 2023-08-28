## Folder structure

This directory contains the implementation of the Go components:
- `cache.go`contains the implementation of the certificate cache.
It provides the cache initialization (`InitializeCache`), `GetMissingCertificatesList` (process first map server response) and `AddCertificatesToCache` (processing second map server response) functionality.
- `validation.go` contains the implementation of the legacy validation. 
It provides the `verifyLegacy` functionality.
- `proofs.go` contains the implementation of some (yet untested) utility
functionality to integrate map server proof validation into the browser extension.
To ease this integration, we have annotated `../main.go` accordingly with `TODO (proof)` indicating where adjustments are necessary once the proofs are available.

- `utils.go` contains some utility functionality for testing.
- The `..._test.go` files contain extensive automated unit test cases.
To run all test cases, execute `go test -v` in the current directory.

`embedded/` is the directory that contains all the files accessible in the implementation via `embed.FS`. 
This directory is statically compiled into the WASM binary via `//go:embed embedded/*` directives.

`embedded/ca-certificates/` contains the mozilla trust root certificates. These certificates are currently used to initialize the cache.
`embedded/unit_test/` contains crypto material used for testing and config files to test legacy validation. If the unit tests fail, the crypto material has likely expired. In this case, uncomment LOCs 105 - 134 of `cache_test.go` for a single run to renew the crypto material.