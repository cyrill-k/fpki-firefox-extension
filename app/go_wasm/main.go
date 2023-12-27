package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go_wasm/cache_v2"
	"log"
	"syscall/js"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
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
type MapServerMissingPayloadsResponse struct {
	CertificateIDs []string
	PolicyIDs      []string
	Payloads       []string
}

type VerifyRequest struct {
	ConnectionCertificateChainb64 []string
}

// initialize all the GO datastructures
// param 1: path to directory containing trust store certificates
// param 2: path to config.js containing the legacy trust preference descriptions
// Note: files must be within cache_v2/embedded
func initializeGODatastructuresWrapper() js.Func {
	jsf := js.FuncOf(func(this js.Value, args []js.Value) any {

		trustStoreDir := args[0].String()
		policyTrustStoreDir := args[1].String()
		configFilePath := args[2].String()

		// initialize certificate cache with root certificates
		// located in trustStoreDir
		nCertificates := cache_v2.InitializeCache(trustStoreDir)

		// same for policies
		nPolicies := cache_v2.InitializePolicyCache(policyTrustStoreDir)

		// initialize validation data structures
		cache_v2.InitializeLegacyTrustPreferences(configFilePath)
		cache_v2.InitializePolicyTrustPreferences(configFilePath)

		nCertificatesAdded := make([]interface{}, 2)
		nCertificatesAdded[0] = nCertificates
		nCertificatesAdded[1] = nPolicies

		return nCertificatesAdded
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
// returns: a list of hashes of all certificates provided as input
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
			certificateParsed.NotAfter = time.Date(2024, 8, 30, 12, 0, 0, 0, time.UTC)
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
		processedCertificates := cache_v2.AddCertificatesToCache(certificatesGo)
		//jsWindow.Set("GoSignature", cache_v2.MSS)
		//jsWindow.Set("GoNCertsAdded", cache_v2.NCertificatesAdded)

		// copy processed certificate hashes into correct format
		processedCertificatesOut := make([]interface{}, len(processedCertificates))
		for i, certificateHash := range processedCertificates {
			processedCertificatesOut[i] = certificateHash
		}

		return processedCertificatesOut
	})
	return jsf
}

func sliceToSet(slice []string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, e := range slice {
		set[e] = struct{}{}
	}
	return set
}

// compute the base64 encoded hash of the base64 encoded payload
func getPayloadAndHash(b64payload string) ([]byte, string) {
	payload, err := base64.StdEncoding.DecodeString(b64payload)
	if err != nil {
		log.Fatal(err)
	}
	h := sha256.New()
	_, err = h.Write(payload)
	if err != nil {
		log.Fatal(err)
	}
	hash := h.Sum(nil)
	return payload, base64.StdEncoding.EncodeToString(hash)
}

// wrapper to make addMissingPayloads visible from JavaScript
// param 1: length of response in bytes
// param 2: map server response containing encoded certificates
// returns: an object containing a list of hashes of all certificates and policies provided as input
func addMissingPayloadsWrapper() js.Func {
	jsf := js.FuncOf(func(this js.Value, args []js.Value) any {
		inputLength := args[1].Int()
		js.CopyBytesToGo(buffer, args[0])

		// var mapserverResponse2Raw MapServerResponse2Raw
		var mapserverResponse MapServerMissingPayloadsResponse
		json.Unmarshal(buffer[:inputLength], &mapserverResponse)

		// split certificates and policies
		certificateMissingIDSet := sliceToSet(mapserverResponse.CertificateIDs)
		fmt.Printf("[Go] cert missing set: %v\n", certificateMissingIDSet)
		policyMissingIDSet := sliceToSet(mapserverResponse.PolicyIDs)
		fmt.Printf("[Go] pol missing set: %v\n", policyMissingIDSet)

		var certificatePayloads []*x509.Certificate
		var certificateHashes []string
		var policyPayloads []*common.PolicyCertificate
		var policyHashes []string
		for _, b64payload := range mapserverResponse.Payloads {
			payload, hash := getPayloadAndHash(b64payload)

			if _, ok := certificateMissingIDSet[hash]; ok {
				certificateParsed, err := x509.ParseCertificate(payload)
				if err != nil {
					panic("failed to parse certificate: " + err.Error())
				}
				certificateParsed.NotAfter = time.Date(2024, 8, 30, 12, 0, 0, 0, time.UTC)
				certificatePayloads = append(certificatePayloads, certificateParsed)
				certificateHashes = append(certificateHashes, hash)
			} else if _, ok := policyMissingIDSet[hash]; ok {
				policy, err := common.FromJSON(payload)
				if err != nil {
					panic("failed to parse policy: " + err.Error())
				}
				policyPayloads = append(policyPayloads, policy.(*common.PolicyCertificate))
				policyHashes = append(policyHashes, hash)
			} else {
				// ignoring payloads that were not requested
				fmt.Printf("Ignoring payload with ID (%v): %v\n", hash, b64payload)
			}
		}

		processedCertificates := cache_v2.AddCertificatesToCache(certificatePayloads)
		processedCertificatesOut := make([]interface{}, len(processedCertificates))
		for i, certificateHash := range processedCertificates {
			processedCertificatesOut[i] = certificateHash
		}

		processedPolicies := cache_v2.AddPoliciesToCache(policyPayloads)
		processedPoliciesOut := make([]interface{}, len(processedPolicies))
		for i, policyHash := range processedPolicies {
			processedPoliciesOut[i] = policyHash
		}

		responseClass := js.Global().Get("AddMissingPayloadsResponseGo")
		return responseClass.New(processedCertificatesOut, processedPoliciesOut)
	})
	return jsf
}

// wrapper to make verifyAndGetMissingIDs visible from JavaScript
// param 1: length of response in bytes
// param 2: map server response containing map server response
// returns: a json object consisting of a MHT proof verification result, a list of hashes of all missing certificates, and a list of hashes of all missing policies
func verifyAndGetMissingIDsWrapper() js.Func {
	jsf := js.FuncOf(func(this js.Value, args []js.Value) any {
		cache_v2.MSS = 0
		cache_v2.NCertificatesAdded = 0

		inputLength := args[1].Int()
		js.CopyBytesToGo(buffer, args[0])

		var responses []mapCommon.MapServerResponse
		json.Unmarshal(buffer[:inputLength], &responses)

		// TODO (cyrill): verify proof

		missingCertificates := make(map[string]struct{})
		missingPolicies := make(map[string]struct{})
		for _, response := range responses {
			certIDs := common.BytesToIDs(response.DomainEntry.CertIDs)
			base64IDs := make([]string, len(certIDs))
			for i, id := range certIDs {
				base64IDs[i] = base64.StdEncoding.EncodeToString(id[:])
			}

			certificates := cache_v2.GetMissingCertificateHashesList(base64IDs)

			uniqueCerts := make(map[string]struct{})
			for _, id := range certificates {
				missingCertificates[id] = struct{}{}
				uniqueCerts[id] = struct{}{}
			}
			if len(uniqueCerts) < len(certificates) {
				fmt.Printf("[Go] Duplicate certificates detected for %s: %v\n", response.DomainEntry.DomainName, certificates)
			}

			policyIDs := common.BytesToIDs(response.DomainEntry.PolicyIDs)
			base64PolicyIDs := make([]string, len(policyIDs))
			for i, id := range policyIDs {
				base64PolicyIDs[i] = base64.StdEncoding.EncodeToString(id[:])
			}

			uniquePolicies := make(map[string]struct{})
			policies := cache_v2.GetMissingPolicyHashesList(base64PolicyIDs)
			for _, id := range policies {
				missingPolicies[id] = struct{}{}
			}
			if len(uniquePolicies) < len(policies) {
				fmt.Printf("[Go] Duplicate policies detected for %s: %v\n", response.DomainEntry.DomainName, policies)
			}
		}

		missingCertificatesOut := []interface{}{}
		for id := range missingCertificates {
			missingCertificatesOut = append(missingCertificatesOut, id)
		}

		missingPoliciesOut := []interface{}{}
		for id := range missingPolicies {
			missingPoliciesOut = append(missingPoliciesOut, id)
		}

		responseClass := js.Global().Get("VerifyAndGetMissingIDsResponseGo")
		return responseClass.New("TODO (MHT VALIDATION)", missingCertificatesOut, missingPoliciesOut)
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
		var verifyLegacyRequest VerifyRequest
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
			legacyTrustInfo.EvaluationResult, legacyTrustInfo.HighestTrustLevel, relevantCASetIDs,
			exampleSubjects, legacyTrustInfo.MaxValidity.Unix())
	})
	return jsf
}

// wrapper to make VerifyPolicy visible from JavaScript
// param 1: the dns name the client connects to
// param 2: JSON encoded certificate chain received in the
// connection attempt
// param 3: length of the JSON encoded certificate chain received in the
// connection attempt
// this function returns a JavaScript object that is cached on the JS side
func verifyPolicyWrapper() js.Func {
	jsf := js.FuncOf(func(this js.Value, args []js.Value) any {

		dnsName := args[0].String()
		inputLength := args[2].Int()
		js.CopyBytesToGo(buffer, args[1])
		var verifyLegacyRequest VerifyRequest
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

		// call the policy validation with the connection domain name and certificate chain
		policyTrustInfo := cache_v2.NewPolicyTrustInfo(dnsName, certificateChain)
		cache_v2.VerifyPolicy(policyTrustInfo)

		// allocate a JS object of type PolicyTrustDecisionGo and pass this
		// object to JS.
		// in JS, this object is being cached, preventing expensive re-validations
		// of the same domain
		policyTrustDecisionClass := js.Global().Get("PolicyTrustDecisionGo")

		// parse output to JS compatible types
		policyChain := make([]interface{}, len(policyTrustInfo.PolicyChain))
		for i, chain := range policyTrustInfo.PolicyChain {
			json, err := common.ToJSON(chain)
			if err != nil {
				panic(err.Error())
			}
			policyChain[i] = string(json)
		}
		conflictingPolicies := make([]interface{}, len(policyTrustInfo.ConflictingPolicyAttributes))
		for i, attributes := range policyTrustInfo.ConflictingPolicyAttributes {
			json, err := json.Marshal(attributes)
			if err != nil {
				panic(err.Error())
			}
			conflictingPolicies[i] = string(json)
		}

		// allocate object to return
		return policyTrustDecisionClass.New(dnsName, policyTrustInfo.EvaluationResult, policyChain, conflictingPolicies, policyTrustInfo.MaxValidity.Unix())
	})
	return jsf
}

func main() {

	// "publish" the functions in JavaScript
	js.Global().Set("initializeGODatastructures", initializeGODatastructuresWrapper())
	js.Global().Set("getMissingCertificatesList", getMissingCertificatesListWrapper())
	js.Global().Set("addCertificatesToCache", addCertificatesToCacheWrapper())
	js.Global().Set("verifyAndGetMissingIDs", verifyAndGetMissingIDsWrapper())
	js.Global().Set("addMissingPayloads", addMissingPayloadsWrapper())
	js.Global().Set("verifyLegacy", verifyLegacyWrapper())
	js.Global().Set("verifyPolicy", verifyPolicyWrapper())

	// prevent WASM from terminating
	<-make(chan bool)

}
