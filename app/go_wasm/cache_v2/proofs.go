package cache_v2

import (
	"bytes"
	"crypto/sha256"
	"log"

	"github.com/netsec-ethz/fpki/pkg/common"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

// TODO: where to get this information from (e.g., fetch from map server?)
// TODO: test functionality and integrate map server proofs
type MapServerInfo struct {
	// some identifier of the map server
	identifier string

	// the public key used to verify the map server's MHT signature
	publicKey any

	// the number of times the map server has misbehaved (e.g., map server
	// does not send a requested certificate)
	nMisbehaviors int
}
type ProofCacheEntry struct {
	// inclusion proof
	poi *mapCommon.PoI

	// map server that sent the inclusion proof
	mapServerInfo *MapServerInfo

	// the map server's tree head signature
	treeHeadSignature []byte

	// the certificate hashes included in the map server's response
	// used to check whether the leaf in the proof is the expected one
	certificateHashes []string

	// the certificate hashes of the certificates that are not yet
	// cached and must be requested from the map server
	missingCertificateHashes map[string]struct{}

	// true if the proof has been validated
	evaluated bool

	// the result of proof validation if the proof
	// has been evaluated
	result bool
}

// cache mapping base64 encoded (leaf hash + map server identifier) to a ProofCacheEntry
var proofCache map[string]*ProofCacheEntry

// helper function to allocate a new ProofCacheEntry
func newProofCacheEntry(poi *mapCommon.PoI, mapServerInfo *MapServerInfo, treeHeadSignature []byte,
	certificateHashes []string) *ProofCacheEntry {
	proofCacheEntry := ProofCacheEntry{
		poi:                      poi,
		mapServerInfo:            mapServerInfo,
		treeHeadSignature:        treeHeadSignature,
		certificateHashes:        certificateHashes,
		missingCertificateHashes: map[string]struct{}{},
		evaluated:                false,
		result:                   false,
	}
	return &proofCacheEntry
}

// TODO: discuss whether this representation of MHT leaf is correct
// assumes leaf := H(base64(H(c1)) || ... || base64(H(cn)))
// checks whether the leafHash received from the map server can be constructed
// from its response
func verifyLeaf(leafHash []byte, leafCertificateHashes []string) bool {
	h := sha256.New()
	for _, certificateHash := range leafCertificateHashes {
		_, err := h.Write([]byte(certificateHash))
		if err != nil {
			log.Fatal(err)
		}
	}
	hash := h.Sum(nil)
	return bytes.Equal(leafHash, hash)
}

func bitIsSet(bits []byte, i int) bool {
	return bits[i/8]&(1<<uint(7-i%8)) != 0
}

// computeMHTBasedOnProof returns the merkle root by hashing the merkle proof items
func computeMHTBasedOnProof(ap [][]byte, keyIndex int, key, leafHash []byte) []byte {
	if keyIndex == len(ap) {
		return leafHash
	}
	if bitIsSet(key, keyIndex) {
		neighbor := computeMHTBasedOnProof(ap, keyIndex+1, key, leafHash)
		result := common.SHA256Hash(ap[len(ap)-keyIndex-1], neighbor)
		return result
	}

	neighbor := computeMHTBasedOnProof(ap, keyIndex+1, key, leafHash)
	result := common.SHA256Hash(neighbor, ap[len(ap)-keyIndex-1])
	return result
}

// verify previously registered proof identified by its proofCache key
func VerifyProof(proofCacheKey string) bool {
	proofCacheEntry, inCache := proofCache[proofCacheKey]

	// if the proof is not yet cached, it cannot be verified
	if !inCache {
		return false
	}

	// if the same proof was already evaluated,
	// return result of previous evaluation
	if proofCacheEntry.evaluated {
		return proofCacheEntry.result
	}

	// check that the leaf hash can be reconstructed from the response
	if !verifyLeaf(proofCacheEntry.poi.ProofValue, proofCacheEntry.certificateHashes) {
		proofCacheEntry.result = false
		proofCacheEntry.evaluated = true
		return proofCacheEntry.result
	}

	// compute MHT root based on the proof, compare against received MHT root
	poi := proofCacheEntry.poi
	computedRoot := computeMHTBasedOnProof(poi.Proof, 0, poi.ProofKey, poi.ProofValue)
	if !bytes.Equal(poi.Root, computedRoot) {
		proofCacheEntry.result = false
		proofCacheEntry.evaluated = true
		return proofCacheEntry.result
	}

	// TODO: check signature with map server public key

	return false
}
