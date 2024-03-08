package cache_v2

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/common/crypto"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// TODO: integrate map server proof validation
// TODO: might want to have a more forgiving error handling
//       (right now, logs fatally)

type PolicyCacheEntry struct {
	// policy to store
	policy *common.PolicyCertificate

	// hash over the policy's immutable fields
	immutableHash string
}

type ImmutablePolicyCacheEntry struct {
	// policies with these immutable fields
	policyHashes []string

	// attributes
	policyAttributes common.PolicyAttributes

	// timestamp
	timestamp time.Time

	// hash over the parent's immutable fields
	immutableIssuerHash string
}

// cache mapping base64 encoded policy hash to a PolicyCacheEntry
var policyCache = map[string]*PolicyCacheEntry{}

// cache mapping base64 encoded hash over the immutable policy
// certificate fields to a PolicyCacheEntry
var immutablePolicyCache = map[string]*ImmutablePolicyCacheEntry{}

// map containing all policy hashes that should be ignored
// (not be requested from the map server again) in the future
// (e.g., because they correspond to expired policies)
var ignoredPolicyHashes = map[string]struct{}{}

// cache mapping a dns name to a list of policy hashes
// of policies that correspond to this dns name
var policyDnsNameCache = map[string][]string{}

// initialize the caches based on the (root) policy certificates in
// the PCA trust store (trust store location: trustStoreDir)
func InitializePolicyCache(trustStoreDir string) int {
	policyCache = map[string]*PolicyCacheEntry{}
	immutablePolicyCache = map[string]*ImmutablePolicyCacheEntry{}
	ignoredPolicyHashes = map[string]struct{}{}
	policyDnsNameCache = map[string][]string{}

	files, err := cacheFileSystem.ReadDir(trustStoreDir)
	if err != nil {
		log.Fatal(err)
	}
	added := 0
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".pc") {
			continue
		}

		// parse trust root certificate
		path := filepath.Join(trustStoreDir, file.Name())
		fileBytes, err := cacheFileSystem.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("initializing with root (%s): %s\n", file, fileBytes)

		policy, err := util.PolicyCertificateFromBytes(fileBytes)
		if err != nil {
			log.Fatalf("loading policy certificate from trust store (%s): %s", path, err)
		}

		policyHash := getPolicyHash(policy)
		immutablePolicyHash := getImmutablePolicyHash(policy)
		immutableIssuerHash := getIssuerHash(policy)

		allocatePolicyCacheEntries(policy, policyHash, immutablePolicyHash, immutableIssuerHash)

		added += 1
	}
	return added
}

// takes a list of certificate hashes
// and returns a list containing all certificate hashes
// from the input that are not yet cached
func GetMissingPolicyHashesList(policyHashes []string) []string {

	var missingPolicyHashes []string
	for _, policyHash := range policyHashes {

		// if the certificate either should be ignored (e.g., we have seen
		// it before and it has expired) or it is already cached,
		// do not include it in the output (it does not have to
		// be requested again)
		_, ignore := ignoredPolicyHashes[policyHash]
		if ignore {
			continue
		}
		if certificateCache[policyHash] == nil {
			missingPolicyHashes = append(missingPolicyHashes, policyHash)
		}
	}
	return missingPolicyHashes
}

// adds a list of certificates to the cache
// TODO: pot. hashing the certificates is unnecessary as the hashes might already
// be available from the first mapserver response
func AddPoliciesToCache(policies []*common.PolicyCertificate) []string {
	nEntriesBefore := len(policyCache)
	now := time.Now()

	// fmt.Printf("policy 0: %v\n", policies[0])
	// create a map of all policies in the request, indicating whether
	// the policy has already been processed
	policiesInRequestProcessed := map[*common.PolicyCertificate]bool{}
	// create a map of all policies for a given hash over the immutable
	// policy fields
	policiesInRequest := map[string][]*common.PolicyCertificate{}
	for _, policy := range policies {
		policiesInRequestProcessed[policy] = false
		immutablePolicyHash := getImmutablePolicyHash(policy)
		v := policiesInRequest[immutablePolicyHash]
		if v == nil {
			policiesInRequest[immutablePolicyHash] = []*common.PolicyCertificate{}
		}
		policiesInRequest[immutablePolicyHash] = append(policiesInRequest[immutablePolicyHash], policy)
	}
	// add all certificates to cache
	// skip certificates that have already been added
	// in a recursive step
	var processedPolicyHashes []string
	for _, policy := range policies {
		if !policiesInRequestProcessed[policy] {
			hashes, added := processPolicy(policy, policiesInRequestProcessed, policiesInRequest)
			processedPolicyHashes = append(processedPolicyHashes, hashes...)
			if added {
				NCertificatesAdded++
			} else {
				fmt.Printf("[Go] Did not add policy: %v\n", policy)
			}
		}
	}
	MS = MS + time.Now().Sub(now).Milliseconds()
	fmt.Printf("[Go] Added %d policies to cache\n", len(policyCache)-nEntriesBefore)
	fmt.Printf("[Go] Total # cache entries: %d\n", len(policyCache))
	fmt.Printf("[Go] Time spent checking signatures: %d ms\n ", MSS)

	MS = 0
	NCertificatesAdded = int64(len(policyCache) - nEntriesBefore)

	return processedPolicyHashes
}

// process a certificate by potentially adding
// it to the cache
// recursively processes parent certificates
// returns the hashes of all processed certificates
func processPolicy(policy *common.PolicyCertificate,
	policiesInRequestProcessed map[*common.PolicyCertificate]bool,
	policiesInRequest map[string][]*common.PolicyCertificate) ([]string, bool) {

	policyHash := getPolicyHash(policy)
	processedPolicyHashes := []string{policyHash}
	immutablePolicyHash := getImmutablePolicyHash(policy)

	// mark the certificate as processed on exit
	defer func() {
		policiesInRequestProcessed[policy] = true
	}()

	// if have already processed the certificate in the request, return whether
	// it was added to the cache
	_, inCache := policyCache[policyHash]
	if policiesInRequestProcessed[policy] || inCache {
		return processedPolicyHashes, inCache
	}
	_, ignored := ignoredPolicyHashes[policyHash]
	if ignored {
		return processedPolicyHashes, false
	}

	// recursively process parent certificates present in the request
	issuerHash := getIssuerHash(policy)
	parentPolicies := policiesInRequest[issuerHash]
	for _, parentPolicy := range parentPolicies {
		if parentHashes, added := processPolicy(parentPolicy, policiesInRequestProcessed, policiesInRequest); added {
			processedPolicyHashes = append(processedPolicyHashes, parentHashes...)
			NCertificatesAdded++
		} else {
			log.Printf("[Go] Did not add policy: %v\n", parentPolicy)
		}
	}

	// now, the cache should be populated with parents (if there were any in the request
	// or already cached)

	// get potential parent certificates of the current certificate
	parentImmutablePolicyCacheEntry, _ := immutablePolicyCache[issuerHash]

	// if no potential parent certificate is present in the cache,
	// cannot add the certificate to the cache
	if parentImmutablePolicyCacheEntry == nil || len(parentImmutablePolicyCacheEntry.policyHashes) == 0 {
		return processedPolicyHashes, false
	}

	// check signature
	potParentPolicy := policyCache[parentImmutablePolicyCacheEntry.policyHashes[0]].policy

	// check that the certificate signature can be verified using the
	// parent certificate and the certificate is currently valid.
	return processedPolicyHashes, verifyPolicyAndAllocateCaches(policy, potParentPolicy, policyHash,
		immutablePolicyHash, issuerHash)
}

// verify child policy with a (pot.) parent certificate and allocate
// cache entries for the child if necessary
// returns true if the policy was added to the cache and false if the
// policy was added to the ignored policies
func verifyPolicyAndAllocateCaches(
	policy *common.PolicyCertificate,
	parentPolicy *common.PolicyCertificate,
	policyHash string,
	immutablePolicyHash string,
	immutableIssuerPolicyHash string) bool {
	err := verifyChildWithParentPolicy(policy, parentPolicy)

	// if policy is a valid child of parentPolicy, allocate new cache entries
	if err == nil {
		allocatePolicyCacheEntries(policy, policyHash, immutablePolicyHash, immutableIssuerPolicyHash)
		return true
	} else {
		// ignore certificate for future requests if it wasn't added to the cache
		// (e.g., because it was already expired)
		ignoredCertificateHashes[policyHash] = struct{}{}
		return false
	}
}

// check a policy against a parent policy
// checks whether parent verifies the child signature.
// if the signature does not verify or some other constraint is violated, returns an error
// otherwise, if the validation succeeds, it returns nil
func verifyChildWithParentPolicy(policy *common.PolicyCertificate, parentPolicy *common.PolicyCertificate) error {
	// TODO (cyrill): do policy validity check: validity period, domain constraints, ...

	// TODO (cyrill): do parent-child validity check: validity period of child is within parent, Child domain is sub-domain of parent domain, ...

	now := time.Now()
	err := crypto.VerifyIssuerSignature(parentPolicy, policy)
	MSS = MSS + time.Now().Sub(now).Milliseconds()
	if err != nil {
		return fmt.Errorf("Failed to verify issuer signature: %s", err)
	}
	return nil
}

// allocate entries in the certificateCache, dnsNameCache, subjectSKICache
// if necessary (for non-root certificates)
func allocatePolicyCacheEntries(policy *common.PolicyCertificate,
	policyHash string,
	immutablePolicyHash string,
	immutableIssuerPolicyHash string) {
	fmt.Printf("allocating policy: imm hash = %s, imm issuer hash = %s\n", immutablePolicyHash, immutableIssuerPolicyHash)

	// add to policy cache
	var policyCacheEntry *PolicyCacheEntry
	policyCacheEntry = &PolicyCacheEntry{
		policy:        policy,
		immutableHash: immutablePolicyHash,
	}
	policyCache[policyHash] = policyCacheEntry

	// allocate new immutableHash entry or adjust existing entry
	immutablePolicyCacheEntry, inCache := immutablePolicyCache[immutablePolicyHash]
	if !inCache {
		immutablePolicyCacheEntry = &ImmutablePolicyCacheEntry{
			policyAttributes:    policy.PolicyAttributes,
			immutableIssuerHash: immutableIssuerPolicyHash,
			timestamp:           policy.TimeStamp,
		}
		immutablePolicyCache[immutablePolicyHash] = immutablePolicyCacheEntry
	}
	immutablePolicyCacheEntry.policyHashes = append(immutablePolicyCacheEntry.policyHashes, policyHash)

	// add to dns cache
	policyDnsNameCache[policy.Domain()] = append(policyDnsNameCache[policy.Domain()], policyHash)
}

// compute the base64 encoded issuer hash field
func getIssuerHash(policy *common.PolicyCertificate) string {
	return base64.StdEncoding.EncodeToString(policy.IssuerHash)
}

// compute the base64 encoded hash over the immutable fields of the
// policy certificate
func getImmutablePolicyHash(policy *common.PolicyCertificate) string {
	hash, err := crypto.ComputeHashAsSigner(policy)
	if err != nil {
		log.Fatalf("Failed to compute hash over immutable policy certificate fields: %s", err)
	}
	return base64.StdEncoding.EncodeToString(hash)
}

// compute the base64 encoded hash of a policy certificate
func getPolicyHash(policy *common.PolicyCertificate) string {
	h := sha256.New()
	json, err := common.ToJSON(policy)
	if err != nil {
		log.Fatalf("Failed to encode policy certificate to JSON: %s", err)
	}
	_, err = h.Write(json)
	if err != nil {
		log.Fatal(err)
	}
	hash := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(hash)
}
