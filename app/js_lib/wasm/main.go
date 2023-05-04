package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"sync"
	"syscall/js"
	"time"
)

// mutex for concurrent writes to cache
var mu sync.Mutex

func getSubjectPublicKeyInfoHash(subjectPublicKeyInfo []byte) string {
	h := sha256.New()
	h.Write(subjectPublicKeyInfo)
	hash := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(hash)

}

// TODO: fill fields of certificateCacheEntryConstructor calls

// function to parse PEM encoded certificates
func parsePEMCertificates(pemCertificatesString string, hashesString string, parentHashesString string) any {

	// get JavaScript constructor
	certificateCacheEntryGoConstructor := js.Global().Get("CertificateCacheEntryGo")

	hashToParsedCertificatesMap := make(map[string]interface{})
	// split the string containing hashes into a list of strings containing a single hash
	var hashes = strings.Split(hashesString, "\n")
	// split the string containing parentHashes into a list of strings containing a single parentHash
	var parentHashes = strings.Split(parentHashesString, "\n")

	// split the string containing all certificates into
	// a list of strings containing a single certificate
	var certificates = strings.Split(pemCertificatesString, ";")
	n_certificates := len(certificates) - 1
	//fmt.Println(n_certificates)
	//fmt.Println(hashes[0])
	//fmt.Println(parentHashes[0])

	// parse each single certificate using Goroutines for parallelism
	var wg sync.WaitGroup
	wg.Add(n_certificates)
	for i := 0; i < n_certificates; i++ {
		ci := i
		go func() {
			block, _ := pem.Decode([]byte(certificates[ci]))
			if block == nil {
				panic("failed to parse certificate PEM")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				panic("failed to parse certificate: " + err.Error())
			}

			var certificate js.Value
			if parentHashes[ci] == "null" {
				certificate = certificateCacheEntryGoConstructor.New(
					cert.Subject.String(),
					cert.Issuer.String(),
					time.Now().UTC().UnixMilli(), // TODO: maybe need to adjust
					base64.StdEncoding.EncodeToString(cert.RawTBSCertificate), // TODO: or just cert.Raw
					nil,
					cert.NotBefore.UnixMilli(),
					cert.NotAfter.UnixMilli(),
					getSubjectPublicKeyInfoHash(cert.RawSubjectPublicKeyInfo),
					nil,
					nil,
				)
			} else {
				certificate = certificateCacheEntryGoConstructor.New(
					cert.Subject.String(),
					cert.Issuer.String(),
					time.Now().UTC().UnixMilli(), // TODO: maybe need to adjust
					base64.StdEncoding.EncodeToString(cert.RawTBSCertificate), // TODO: or just cert.Raw
					parentHashes[ci],
					cert.NotBefore.UnixMilli(),
					cert.NotAfter.UnixMilli(),
					getSubjectPublicKeyInfoHash(cert.RawSubjectPublicKeyInfo),
					nil,
					nil,
				)
			}
			// create JavaScript type

			// append certificate to list
			mu.Lock()
			hashToParsedCertificatesMap[hashes[ci]] = certificate
			mu.Unlock()
			wg.Done()
		}()
	}
	wg.Wait()

	return hashToParsedCertificatesMap
}

func parsePEMCertificatesWrapper() js.Func {
	jsf := js.FuncOf(func(this js.Value, args []js.Value) any {

		// call function
		return parsePEMCertificates(args[0].String(), args[1].String(), args[2].String())

	})
	return jsf
}

func main() {

	js.Global().Set("parsePEMCertificates", parsePEMCertificatesWrapper())
	//js.Global().Set("parsePEMCertificateIterate", parsePEMCertificateIterateWrapper())

	// prevent program from terminating
	<-make(chan bool)

}
