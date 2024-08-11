package cache_v2

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"sort"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/common/crypto"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
	"github.com/netsec-ethz/fpki/pkg/util"
)

type MapServerInfo struct {
	// some identifier of the map server
	identifier string

	// TODO: allow for other algorithms than RSA
	// the public key used to verify the map server's MHT signature
	publicKey *rsa.PublicKey
}

type ProofCacheEntry struct {
	// inclusion proof
	poi *mapCommon.PoI

	// the map server's tree head signature
	treeHeadSignature []byte

	// the certificate hashes included in the map server's response
	// used to check whether the leaf in the proof is the expected one
	// sorted based on their byte representation
	sortedCertificateHashes []*common.SHA256Output

	// leaf hash (i.e., sha256 hash of sorted concatenated certificate hashes)
	calculatedLeafHash []byte

	// proof key value (i.e., sha256 hash of domain)
	calculatedProofKey []byte

	// map server that sent the inclusion proof
	mapserverID string

	// true if the proof has been validated
	evaluated bool

	// the result of proof validation if the proof
	// has been evaluated
	result bool

	// the last encountered error (if any error occurred)
	lastError error
}

func (e *ProofCacheEntry) Evaluated() bool {
	return e.evaluated
}

func (e *ProofCacheEntry) Result() bool {
	return e.result
}

func (e *ProofCacheEntry) LastError() error {
	return e.lastError
}

// map server info cache
var mapserverInfoCache = map[string]*MapServerInfo{}

// cache mapping base64 encoded (leaf hash + map server identifier) to a ProofCacheEntry
var proofCache = map[string]*ProofCacheEntry{}

func InitializeMapserverInfoCache(configMap map[string]interface{}) bool {
	mapserverInfoCache = map[string]*MapServerInfo{}
	proofCache = map[string]*ProofCacheEntry{}

	identities := []string{}
	mapserversJSON := configMap["mapservers"].([]interface{})
	for _, entryInterface := range mapserversJSON {
		entry := entryInterface.(map[string]interface{})
		id := entry["identity"].(string)
		publicKeyDERBase64, ok := entry["publickey"]
		if ok {
			publicKey, err := util.DERBase64ToRSAPublic(publicKeyDERBase64.(string))
			if err != nil {
				log.Panicf("Cannot extract RSA public key from DER: %s", err)
			}
			mapserverInfoCache[id] = &MapServerInfo{identifier: id, publicKey: publicKey}
			identities = append(identities, id)
		} else {
			fmt.Printf("Ignoring map server without public key: %s\n", id)
		}
	}
	fmt.Printf("Added %d map servers: %s\n", len(identities), identities)
	return true
}

// MHT proof verifications are cached to ensure they only need to be verified once.
// The key is calculated as follows: hash(hash(domain), hash(leaf), mapserverID)
func GetProofCacheKey(proofKey []byte, leafHash []byte, mapserverID string) (string, error) {
	h := sha256.New()
	_, err := h.Write(proofKey)
	if err != nil {
		return "", fmt.Errorf("Failed to write proof key: %s", err)
	}
	_, err = h.Write(leafHash)
	if err != nil {
		return "", fmt.Errorf("Failed to write leaf hash: %s", err)
	}
	_, err = h.Write([]byte(mapserverID))
	if err != nil {
		return "", fmt.Errorf("Failed to write mapserver ID: %s", err)
	}
	hash := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(hash), nil
}

// add a new cache entry for this map server response if it does not exist yet and return the key used in the cache
func AddMapServerResponseToCacheIfNecessary(response mapCommon.MapServerResponse, certIDs, policyIDs []*common.SHA256Output, mapserverID string) (string, error) {
	// merge and sort cert and policy IDs
	ids := append(certIDs[:0:0], certIDs...)
	ids = append(ids, policyIDs...)
	sort.Slice(ids, func(i, j int) bool {
		return bytes.Compare(ids[i][:], ids[j][:]) == -1
	})

	// generate proof key
	proofKey := common.SHA256Hash([]byte(response.DomainEntry.DomainName))

	// calculate leaf hash to compare leaf values in PoPs (ignored in PoAs)
	concatenatedLeafHashes := common.IDsToBytes(ids)
	leafHash := common.SHA256Hash(concatenatedLeafHashes)

	// add entry to cache if necessary
	proofCacheKey, err := GetProofCacheKey(proofKey, leafHash, mapserverID)
	if err != nil {
		return "", err
	}
	if _, ok := proofCache[proofCacheKey]; !ok {
		proofCache[proofCacheKey] = newProofCacheEntry(&response.PoI, proofKey, mapserverID, response.TreeHeadSig, ids, leafHash)
	}
	return proofCacheKey, nil
}

// helper function to allocate a new ProofCacheEntry
func newProofCacheEntry(poi *mapCommon.PoI, proofKey []byte, mapserverID string, treeHeadSignature []byte,
	sortedCertificateHashes []*common.SHA256Output, leafHash []byte) *ProofCacheEntry {
	proofCacheEntry := ProofCacheEntry{
		poi:                     poi,
		treeHeadSignature:       treeHeadSignature,
		sortedCertificateHashes: sortedCertificateHashes,
		calculatedLeafHash:      leafHash,
		calculatedProofKey:      proofKey,
		mapserverID:             mapserverID,
		evaluated:               false,
		result:                  false,
		lastError:               nil,
	}
	return &proofCacheEntry
}

// verify previously registered proof identified by its proofCache key
func VerifyProof(proofCacheKey string) *ProofCacheEntry {
	proofCacheEntry, inCache := proofCache[proofCacheKey]

	// if the proof is not yet cached, it cannot be verified
	if !inCache {
		return nil
	}
	poi := proofCacheEntry.poi

	// if the same proof was already evaluated,
	// return result of previous evaluation
	if proofCacheEntry.evaluated {
		return proofCacheEntry
	}

	if poi.ProofType == mapCommon.PoP {
		// for PoP, check that the leaf hash can be reconstructed from the response
		if !bytes.Equal(poi.ProofValue, proofCacheEntry.calculatedLeafHash) {
			proofCacheEntry.result = false
			proofCacheEntry.evaluated = true
			proofCacheEntry.lastError = fmt.Errorf("MHT leaf hashes do not match: %x (provided by mapserver) %x (calculated)", poi.ProofValue, proofCacheEntry.calculatedLeafHash)
			return proofCacheEntry
		}
	} else {
		// for PoA, ensure that no certificates were returned for this leaf
		if len(proofCacheEntry.sortedCertificateHashes) > 0 {
			proofCacheEntry.result = false
			proofCacheEntry.evaluated = true
			proofCacheEntry.lastError = fmt.Errorf("Returned non-inclusion proof with existing certificates")
			return proofCacheEntry
		}
	}

	// compute MHT root based on the proof and compare against received MHT root
	if poi.ProofType == mapCommon.PoP {
		if !trie.VerifyInclusion(poi.Root, poi.Proof, proofCacheEntry.calculatedProofKey, poi.ProofValue) {
			proofCacheEntry.result = false
			proofCacheEntry.evaluated = true
			proofCacheEntry.lastError = fmt.Errorf("Failed to validate inclusion proof")
			return proofCacheEntry
		}
	} else {
		if !trie.VerifyNonInclusion(poi.Root, poi.Proof, proofCacheEntry.calculatedProofKey, poi.ProofValue, poi.ProofKey) {
			proofCacheEntry.result = false
			proofCacheEntry.evaluated = true
			proofCacheEntry.lastError = fmt.Errorf("Failed to validate non-inclusion proof")
			return proofCacheEntry
		}
	}

	// verify the STH signature
	err := crypto.VerifySignedBytes(poi.Root, proofCacheEntry.treeHeadSignature, mapserverInfoCache[proofCacheEntry.mapserverID].publicKey)
	if err != nil {
		proofCacheEntry.result = false
		proofCacheEntry.evaluated = true
		proofCacheEntry.lastError = fmt.Errorf("Failed to verify signature: %s", err)
		return proofCacheEntry
	}

	proofCacheEntry.result = true
	proofCacheEntry.evaluated = true
	return proofCacheEntry
}
