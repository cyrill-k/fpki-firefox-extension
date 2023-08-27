package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"go_wasm/cache_v2"
	"syscall/js"
	"time"
)

// NOTE: This file contains a lot of commented timing information
// that can be used to get more detailed microbenchmarks

// scratch memory to store raw inputs from JS in (50 MB)
const SCRATCH_MEM_SIZE = 50000000

var buffer = make([]byte, SCRATCH_MEM_SIZE)

type MapServerResponse1Raw struct {
	Hashesb64 []string
}
type MapServerResponse2Raw struct {
	Certificatesb64 []string
}

type VerifyLegacyRequest struct {
	ConnectionCertificateChainb64 []string
}

// initialize all the GO datastructures
// param 1: path to directory containing trust store certificates
// param 2: path to config.js containing the legacy trust preference descriptions
// Note: files must be within cache_v2/embedded
func initializeGODatastructuresWrapper() js.Func {
	jsf := js.FuncOf(func(this js.Value, args []js.Value) any {

		trustStoreDir := args[0].String()
		configFilePath := args[1].String()

		// initialize certificate cache with root certificates
		// located in trustStoreDir
		nCertificates := cache_v2.InitializeCache(trustStoreDir)

		// initialize validation data structures
		cache_v2.InitializeLegacyTrustPreferences(configFilePath)

		return nCertificates
	})
	return jsf

}

// wrapper to make GetMissingCertificateHashesList visible from JavaScript
// param 1: bytes encoding the JSON response of the map server
// param 2: length of response in bytes
func getMissingCertificatesListWrapper() js.Func {
	jsf := js.FuncOf(func(this js.Value, args []js.Value) any {
		//jsWindow := js.Global().Get("window")
		inputLength := args[1].Int()

		//tn := time.Now()
		js.CopyBytesToGo(buffer, args[0])
		//te := time.Now()
		//fmt.Printf("[Go] getMissingCertificatesList copying input bytes took %d ms \n", time.Now().Sub(tn).Milliseconds())
		//jsWindow.Set("GoCopy", te.Sub(tn).Milliseconds())

		/*
			tn = time.Now()
			base64DecodedLen, err := base64.StdEncoding.Decode(buffer[inputLength:], buffer[:inputLength])
			te = time.Now()
			fmt.Printf("[Go] getMissingCertificatesList base64decode took %d ms \n", time.Now().Sub(tn).Milliseconds())
			jsWindow.Set("Gob64Decode", te.Sub(tn).Milliseconds())
			if err != nil {
				panic(err.Error())
			}

		*/
		var mapserverResponse1Raw MapServerResponse1Raw
		//tn = time.Now()
		json.Unmarshal(buffer[:inputLength], &mapserverResponse1Raw)
		//te = time.Now()
		//jsWindow.Set("GoJSONDecode", te.Sub(tn).Milliseconds())
		//fmt.Printf("[Go] getMissingCertificatesList unmarshalling JSON took %d ms \n", time.Now().Sub(tn).Milliseconds())

		// TODO (proof): verify Proof (if necessary), allocate proofCache Entry (if necessary), else return

		// call function to determine which certificate hashes are not yet cached
		missingLeafCertificates := cache_v2.GetMissingCertificateHashesList(mapserverResponse1Raw.Hashesb64)

		// TODO (proof): add an entry in proofCacheEntry.missingCertificateHashes for each missingLeafCertificate

		// copy missing certificate hashes into correct format
		missingLeafCertificatesOut := make([]interface{}, len(missingLeafCertificates))
		for i, certificateHash := range missingLeafCertificates {
			missingLeafCertificatesOut[i] = certificateHash
		}

		// TODO (proof): include proofCacheEntry key in output, and pass it
		// in corresponding AddCertificatesToCache call
		return missingLeafCertificatesOut
	})
	return jsf
}

// wrapper to make addCertificatesToCache visible from JavaScript
// param 1: length of response in bytes
// param 2: map server response containing PEM encoded certificates
func addCertificatesToCacheWrapper() js.Func {
	jsf := js.FuncOf(func(this js.Value, args []js.Value) any {
		cache_v2.MSS = 0
		cache_v2.NCertificatesAdded = 0
		//jsWindow := js.Global().Get("window")

		inputLength := args[1].Int()
		//tn := time.Now()
		js.CopyBytesToGo(buffer, args[0])
		//te := time.Now()
		//jsWindow.Set("GoCopy", te.Sub(tn).Milliseconds())
		//fmt.Printf("[Go] addCertificatesToCache copying input bytes took %d ms \n", te.Sub(tn).Milliseconds())

		/*
			tn = time.Now()
			base64DecodedLen, err := base64.StdEncoding.Decode(buffer[inputLength:], buffer[:inputLength])
					if err != nil {
					panic(err.Error())
				}

				te = time.Now()
				var timeDecodeNS int64 = te.Sub(tn).Nanoseconds()


		*/
		//var timeDecodeNS int64 = 0
		//var timeParseNS int64 = 0

		var mapserverResponse2Raw MapServerResponse2Raw
		//tn = time.Now()
		json.Unmarshal(buffer[:inputLength], &mapserverResponse2Raw)
		//te = time.Now()
		//jsWindow.Set("GoJSONDecode", te.Sub(tn).Milliseconds())
		//fmt.Printf("[Go] addCertificatesToCache unmarshalling JSON took %d ms \n", te.Sub(tn).Milliseconds())

		// parse the certificates
		nCertificates := len(mapserverResponse2Raw.Certificatesb64)
		certificatesGo := make([]*x509.Certificate, nCertificates)
		for i := 0; i < nCertificates; i++ {
			//tnn := time.Now()
			certificateDER, err := base64.StdEncoding.DecodeString(mapserverResponse2Raw.Certificatesb64[i])
			if err != nil {
				panic(err.Error())
			}
			//timeDecodeNS = timeDecodeNS + time.Now().Sub(tnn).Nanoseconds()
			//tn = time.Now()
			certificateParsed, err := x509.ParseCertificate(certificateDER)
			if err != nil {
				panic("failed to parse certificate: " + err.Error())
			}
			//te = time.Now()
			//timeParseNS = timeParseNS + te.Sub(tn).Nanoseconds()

			// TODO: remove this line after evaluation, it is only used because most
			// certificates in the log server are expired currently
			certificateParsed.NotAfter = time.Date(2023, 8, 30, 12, 0, 0, 0, time.UTC)
			certificatesGo[i] = certificateParsed

			// TODO (proof): check that certificate is in proofCacheEntry.missingCertificateHashes (identified by key passed as input)
			// and delete it from proofCacheEntry.missingCertificateHashes
		}
		//jsWindow.Set("Gob64Decode", timeDecodeNS/1000000)
		//fmt.Printf("[Go] addCertificatesToCache base64decode took %d ms \n", timeDecodeNS/1000000)

		// TODO (proof): check that len(proofCacheEntry.missingCertificateHashes) == 0, otherwise register a misbehavior
		// (increase proofCacheEntry.mapserver.nMisbehaviors) AND act accordingly (discuss)
		//fmt.Printf("[Go] parsing %d certificates took %d ms \n", nCertificates, te.Sub(tn).Milliseconds())
		//jsWindow.Set("GoParseCertificates", timeParseNS/1000000)

		// add parsed certificates to cache
		cache_v2.AddCertificatesToCache(certificatesGo)
		//jsWindow.Set("GoSignature", cache_v2.MSS)
		//jsWindow.Set("GoNCertsAdded", cache_v2.NCertificatesAdded)

		return nil
	})
	return jsf
}

// wrapper to make VerifyLegacy visible from JavaScript
// param 1: the dns name the client connects to
// param 2: JSON encoded certificate chain received in the
// connection attempt
// param 3: length of the JSON encoded certificate chain received in the
// connection attempt
// this function returns a JavaScript object that is cached on the JS side
func verifyLegacyWrapper() js.Func {
	jsf := js.FuncOf(func(this js.Value, args []js.Value) any {

		dnsName := args[0].String()
		inputLength := args[2].Int()
		js.CopyBytesToGo(buffer, args[1])
		var verifyLegacyRequest VerifyLegacyRequest
		json.Unmarshal(buffer[:inputLength], &verifyLegacyRequest)
		nCertificates := len(verifyLegacyRequest.ConnectionCertificateChainb64)

		// parse certificate chain
		certificateChain := make([]*x509.Certificate, nCertificates)
		for i := 0; i < nCertificates; i++ {
			certificateDER, err := base64.StdEncoding.DecodeString(verifyLegacyRequest.ConnectionCertificateChainb64[i])
			if err != nil {
				panic(err.Error())
			}
			certificateParsed, err := x509.ParseCertificate(certificateDER)
			if err != nil {
				panic("failed to parse certificate: " + err.Error())
			}
			certificateChain[i] = certificateParsed
		}

		// call the Legacy validation with the connection domain name and certificate chain
		legacyTrustInfo := cache_v2.NewLegacyTrustInfo(dnsName, certificateChain)
		cache_v2.VerifyLegacy(legacyTrustInfo)

		// allocate a JS object of type LegacyTrustDecisionGo and pass this
		// object to JS.
		// in JS, this object is being cached, preventing expensive re-validations
		// of the same domain
		legacyTrustDecisionClass := js.Global().Get("LegacyTrustDecisionGo")

		// parse output to JS compatible types
		relevantCASetIDs := make([]interface{}, len(legacyTrustInfo.RelevantCASetIDs))
		for i, caSetID := range legacyTrustInfo.RelevantCASetIDs {
			relevantCASetIDs[i] = caSetID
		}
		exampleSubjects := make([]interface{}, len(legacyTrustInfo.ExampleSubjects))
		for i, exampleSubject := range legacyTrustInfo.ExampleSubjects {
			exampleSubjects[i] = exampleSubject
		}

		// allocate object to return
		return legacyTrustDecisionClass.New(dnsName, legacyTrustInfo.ConnectionTrustLevel,
			legacyTrustInfo.ConnectionRelevantCASetID, legacyTrustInfo.ConnectionExampleSubject,
			legacyTrustInfo.EvaluationResult, relevantCASetIDs,
			exampleSubjects, legacyTrustInfo.MaxValidity.Unix(), legacyTrustInfo.HighestTrustLevel)
	})
	return jsf
}

func main() {

	// "publish" the functions in JavaScript
	js.Global().Set("initializeGODatastructures", initializeGODatastructuresWrapper())
	js.Global().Set("getMissingCertificatesList", getMissingCertificatesListWrapper())
	js.Global().Set("addCertificatesToCache", addCertificatesToCacheWrapper())
	js.Global().Set("verifyLegacy", verifyLegacyWrapper())

	// prevent WASM from terminating
	<-make(chan bool)

}
