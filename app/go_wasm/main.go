package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go_wasm/cache_v2"
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
		configJSON := args[2].String()

		// initialize certificate cache with root certificates
		// located in trustStoreDir
		nCertificates := cache_v2.InitializeCache(trustStoreDir)

		// same for policies
		nPolicies := cache_v2.InitializePolicyCache(policyTrustStoreDir)

		// decode JSON config
		var configMap map[string]interface{}
		json.Unmarshal([]byte(configJSON), &configMap)

		// initialize validation data structures
		cache_v2.InitializeLegacyTrustPreferences(configMap)
		cache_v2.InitializePolicyTrustPreferences(configMap)

		// initialize map server info cache
		cache_v2.InitializeMapserverInfoCache(configMap)

		nCertificatesAdded := make([]interface{}, 2)
		nCertificatesAdded[0] = nCertificates
		nCertificatesAdded[1] = nPolicies

		return nCertificatesAdded
	})
	return jsf
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
		certificateMissingIDSet := cache_v2.SliceToSet(mapserverResponse.CertificateIDs)
		fmt.Printf("[Go] cert missing set: %v\n", certificateMissingIDSet)
		policyMissingIDSet := cache_v2.SliceToSet(mapserverResponse.PolicyIDs)
		fmt.Printf("[Go] pol missing set: %v\n", policyMissingIDSet)

		var certificatePayloads []*x509.Certificate
		var certificateHashes []string
		var policyPayloads []*common.PolicyCertificate
		var policyHashes []string
		for _, b64payload := range mapserverResponse.Payloads {
			payload, hash := cache_v2.GetPayloadAndHash(b64payload)

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
		processedCertificatesOut := cache_v2.TransformListToInterfaceType(processedCertificates)

		processedPolicies := cache_v2.AddPoliciesToCache(policyPayloads)
		processedPoliciesOut := cache_v2.TransformListToInterfaceType(processedPolicies)

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

		mapserverID := args[0].String()
		inputLength := args[2].Int()
		js.CopyBytesToGo(buffer, args[1])

		var responses []mapCommon.MapServerResponse
		json.Unmarshal(buffer[:inputLength], &responses)

		mhtProofVerificationResults := []string{}
		missingCertificates := make(map[string]struct{})
		missingPolicies := make(map[string]struct{})
		for _, response := range responses {
			certIDs := common.BytesToIDs(response.DomainEntry.CertIDs)
			base64IDs := make([]string, len(certIDs))
			for i, id := range certIDs {
				base64IDs[i] = base64.StdEncoding.EncodeToString(id[:])
			}

			policyIDs := common.BytesToIDs(response.DomainEntry.PolicyIDs)
			base64PolicyIDs := make([]string, len(policyIDs))
			for i, id := range policyIDs {
				base64PolicyIDs[i] = base64.StdEncoding.EncodeToString(id[:])
			}

			// verify MHT proof
			proofCacheKey, err := cache_v2.AddMapServerResponseToCacheIfNecessary(response, certIDs, policyIDs, mapserverID)
			if err != nil {
				mhtProofVerificationResults = append(mhtProofVerificationResults, "Failed to add map server response to cache: "+err.Error())
				continue
			}
			proofEntry := cache_v2.VerifyProof(proofCacheKey)
			var verificationResult string
			if proofEntry == nil {
				mhtProofVerificationResults = append(mhtProofVerificationResults, "Failed to add entry to proof cache")
				continue
			} else if !proofEntry.Evaluated() || !proofEntry.Result() {
				verificationResult := fmt.Sprintf("MHT Verification for %s and map server %s failed", response.DomainEntry.DomainName, mapserverID)
				if proofEntry.LastError() != nil {
					verificationResult += fmt.Sprintf(": %s", proofEntry.LastError().Error())
				}
				mhtProofVerificationResults = append(mhtProofVerificationResults, verificationResult)
				continue
			} else {
				verificationResult = "success"
				mhtProofVerificationResults = append(mhtProofVerificationResults, verificationResult)
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

			policies := cache_v2.GetMissingPolicyHashesList(base64PolicyIDs)
			uniquePolicies := make(map[string]struct{})
			for _, id := range policies {
				missingPolicies[id] = struct{}{}
				uniquePolicies[id] = struct{}{}
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

		mhtValidationResultsOut := cache_v2.TransformListToInterfaceType(mhtProofVerificationResults)

		responseClass := js.Global().Get("VerifyAndGetMissingIDsResponseGo")
		return responseClass.New(mhtValidationResultsOut, missingCertificatesOut, missingPoliciesOut)
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
		relevantCASetIDs := cache_v2.TransformListToInterfaceType(legacyTrustInfo.HighestTrustLevelCASets)
		relevantCertificateChainIndices := cache_v2.TransformListToInterfaceType(legacyTrustInfo.HighestTrustLevelChainIndices)
		relevantChainCertificateHashes := cache_v2.TransformNestedListsToInterfaceType(legacyTrustInfo.HighestTrustLevelChainHashes)
		relevantChainCertificateSubjects := cache_v2.TransformNestedListsToInterfaceType(legacyTrustInfo.HighestTrustLevelChainSubjects)

		// allocate object to return
		return legacyTrustDecisionClass.New(dnsName, legacyTrustInfo.ConnectionTrustLevel,
			legacyTrustInfo.ConnectionTrustLevelCASet, legacyTrustInfo.ConnectionTrustLevelChainIndex,
			legacyTrustInfo.EvaluationResult, legacyTrustInfo.HighestTrustLevel, relevantCASetIDs,
			relevantCertificateChainIndices, relevantChainCertificateHashes, relevantChainCertificateSubjects, legacyTrustInfo.MaxValidity.Unix())
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
		return policyTrustDecisionClass.New(dnsName, policyTrustInfo.EvaluationResult, policyChain, conflictingPolicies, policyTrustInfo.MaxValidity.Unix(), policyTrustInfo.DomainExcluded)
	})
	return jsf
}

func main() {
	// "publish" the functions in JavaScript
	js.Global().Set("initializeGODatastructures", initializeGODatastructuresWrapper())
	js.Global().Set("verifyAndGetMissingIDs", verifyAndGetMissingIDsWrapper())
	js.Global().Set("addMissingPayloads", addMissingPayloadsWrapper())
	js.Global().Set("verifyLegacy", verifyLegacyWrapper())
	js.Global().Set("verifyPolicy", verifyPolicyWrapper())

	// prevent WASM from terminating
	<-make(chan bool)
}
