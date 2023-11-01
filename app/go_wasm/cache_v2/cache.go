package cache_v2

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"
)

// TODO: integrate map server proof validation
// TODO: ensure that functions calculating hashes use
// TODO: might want to have a more forgiving error handling
//       (right now, logs fatally)
// the same format as the map server

type CertificateCacheEntry struct {
	// certificate to store
	certificate *x509.Certificate

	// identifier of potential parent certificates
	// (base64 encoded string of hash of issuer's identifier)
	// the issuer identifier is its Subject and Subject key ID
	issuerAKIHash string

	// flag indicating whether the certificate is a trust root
	trustRoot bool
}

type SubjectSKICacheEntry struct {
	// set of certificates with the same Subject and SubjectKeyID
	certificates map[string]struct{}
}

// store certificate chain and additional information about the chain
// (e.g., if constraints (e.g., name constraints) need to be checked)
// to check validity of the chain
type CertificateChainInfo struct {
	// certificate chain starting with a leaf and ending with a root
	certificateChain []*x509.Certificate

	// flag indicating whether the chain contains
	// constraints that pot. need to be checked
	// (e.g., name constraint, path length constraints, ...)
	constraintsApply bool
}

// cache mapping base64 encoded certificate hash to a CertificateCacheEntry
var certificateCache = map[string]*CertificateCacheEntry{}

// cache mapping the base64 encoded hash of <certificate.Subject, certificate.SKI>
// to a SubjectSKICacheEntry
var subjectSKICache = map[string]*SubjectSKICacheEntry{}

// cache mapping a dns name to a list of certificate hashes
// of leaf certificates that correspond to this dns name
var dnsNameCache = map[string][]string{}

// map containing all certificate hashes that should be ignored
// (not be requested from the map server again) in the future
// (e.g., because they correspond to expired certificates)
var ignoredCertificateHashes = map[string]struct{}{}

// reasons why a certificate should be ignored
// TODO: maybe include other reasons in the future
var ignoreReasons []x509.InvalidReason = []x509.InvalidReason{x509.Expired}

// whitelist some unhandled critical extensions (e.g., CT poison, CT key usage).
// we need to consider certificates with CT extensions in the cache as they describe
// actual existing leaf certificates
var CTPoison = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
var CTKeyUsage = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}
var UnhandledCriticalExtensionWhitelist = []asn1.ObjectIdentifier{CTPoison, CTKeyUsage}

// enable read access to files within embedded directory
//
//go:embed embedded/*
var cacheFileSystem embed.FS

// some variables used to measure runtime
var MS int64 = 0
var MSS int64 = 0
var NCertificatesAdded int64 = 0

// remove extensions present in UnhandledCriticalExtensionWhitelist from the
// certificate's UnhandledCriticalExtensions
func removeWhitelistedUnhandledCriticalExtensions(certificate *x509.Certificate) {
	if certificate.UnhandledCriticalExtensions != nil {
		unhandledCriticalExtensionsFiltered := []asn1.ObjectIdentifier{}
		for _, criticalExtension := range certificate.UnhandledCriticalExtensions {
			addCriticalExtension := true
			for _, whitelistedCriticalExtension := range UnhandledCriticalExtensionWhitelist {
				if criticalExtension.Equal(whitelistedCriticalExtension) {
					addCriticalExtension = false
				}
			}
			if addCriticalExtension {
				unhandledCriticalExtensionsFiltered = append(unhandledCriticalExtensionsFiltered, criticalExtension)
			}
		}
		certificate.UnhandledCriticalExtensions = unhandledCriticalExtensionsFiltered
	}
}

// helper function to allocate a new SubjectSKICacheEntry
// containing an empy certificates set
func newSubjectSKICacheEntry() *SubjectSKICacheEntry {
	subjectSKICacheEntry := SubjectSKICacheEntry{
		certificates: map[string]struct{}{},
	}
	return &subjectSKICacheEntry
}

// compute the base64 encoded hash of certificate.Raw
func GetRawCertificateHash(certificate *x509.Certificate) string {
	h := sha256.New()
	_, err := h.Write(certificate.Raw)
	if err != nil {
		log.Fatal(err)
	}
	hash := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(hash)
}

// compute the base64 encoded hash of <certificate.Subject, certificate.SubjectKeyId>
func GetRawCertificateSubjectSKIHash(certificate *x509.Certificate) string {
	h := sha256.New()
	_, err := h.Write([]byte(certificate.Subject.String()))
	if err != nil {
		log.Fatal(err)
	}

	// if the certificate is a leaf, use RawSubjectPublicKeyInfo as SKI
	if certificate.IsCA {
		_, err = h.Write(certificate.SubjectKeyId)
	} else {
		_, err = h.Write(certificate.RawSubjectPublicKeyInfo)
	}

	if err != nil {
		log.Fatal(err)
	}
	hash := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(hash)
}

// compute the base64 encoded hash of <certificate.Issuer, certificate.AuthorityKeyId>
func GetRawCertificateIssuerAKIHash(certificate *x509.Certificate) string {
	h := sha256.New()
	_, err := h.Write([]byte(certificate.Issuer.String()))
	if err != nil {
		log.Fatal(err)
	}
	_, err = h.Write(certificate.AuthorityKeyId)
	if err != nil {
		log.Fatal(err)
	}
	hash := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(hash)
}

// initialize the caches based on the certificates in
// the trust store (trust store location: trustStoreDir)
func InitializeCache(trustStoreDir string) int {

	files, err := cacheFileSystem.ReadDir(trustStoreDir)
	if err != nil {
		log.Fatal(err)
	}
	added := 0
	for _, file := range files {

		// parse trust root certificate
		fileBytes, err := cacheFileSystem.ReadFile(trustStoreDir + "/" + file.Name())
		if err != nil {
			log.Fatal(err)
		}
		var block *pem.Block
		block, rem := pem.Decode(fileBytes)
		if len(rem) > 0 {
			log.Fatalf("Error during parsing of trust root PEM: %s", file.Name())
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		// add certificate to the caches as trust root
		certificateHash := GetRawCertificateHash(certificate)
		certificateSubjectSKIHash := GetRawCertificateSubjectSKIHash(certificate)
		certificateCacheEntry := &CertificateCacheEntry{
			certificate:   certificate,
			issuerAKIHash: certificateSubjectSKIHash, // self-issued
			trustRoot:     true,
		}
		certificateCache[certificateHash] = certificateCacheEntry

		subjectSKICacheEntry, cached := subjectSKICache[certificateSubjectSKIHash]
		if !cached {
			subjectSKICacheEntry = newSubjectSKICacheEntry()
			subjectSKICache[certificateSubjectSKIHash] = subjectSKICacheEntry
		}
		subjectSKICacheEntry.certificates[certificateHash] = struct{}{}

		added += 1
	}
	return added
}

// takes a list of certificate hashes
// and returns a list containing all certificate hashes
// from the input that are not yet cached
func GetMissingCertificateHashesList(certificateHashes []string) []string {

	var missingCertificateHashes []string
	for _, certificateHash := range certificateHashes {

		// if the certificate either should be ignored (e.g., we have seen
		// it before and it has expired) or it is already cached,
		// do not include it in the output (it does not have to
		// be requested again)
		_, ignore := ignoredCertificateHashes[certificateHash]
		if ignore {
			continue
		}
		if certificateCache[certificateHash] == nil {
			missingCertificateHashes = append(missingCertificateHashes, certificateHash)
		}
	}
	return missingCertificateHashes
}

// check whether specific certificate validation error
// should be ignored (added to ignoredCertificateHashes)
func ignoreError(err error) bool {
	certificateInvalidError, ok := err.(x509.CertificateInvalidError)
	if ok {
		for _, ignoreReason := range ignoreReasons {
			if certificateInvalidError.Reason == ignoreReason {
				return true
			}
		}
		return false
	} else {
		return false
	}
}

// check a certificate against a parent certificate
// checks whether parent verifies the child signature and the child's
// validity period.
// the first return value indicates whether these checks all succeeded
// the second return value indicates whether the certificate should still
// be remembered in case of a failing check
func verifyChildWithParentCertificate(certificate *x509.Certificate, parentCertificate *x509.Certificate) (bool, bool) {

	var errs []error

	// NOTE: this check only checks whether the certificate is currently valid
	// (as we treat even non-leaf certificates as leafs here)
	// this eases error handling, as all errors are x509 specific
	err := certificate.IsValid(x509.LeafCertificate, []*x509.Certificate{}, &x509.VerifyOptions{})
	if err != nil {
		errs = append(errs, err)
	}

	now := time.Now()

	// check signature
	err = certificate.CheckSignatureFrom(parentCertificate)
	if err != nil {
		errs = append(errs, err)
	}

	for _, err = range errs {
		if !ignoreError(err) {
			return false, false
		}
	}

	// track total time spent doing signature checks
	MSS = MSS + time.Now().Sub(now).Milliseconds()
	return len(errs) == 0, true
}

// allocate entries in the certificateCache, dnsNameCache, subjectSKICache
// if necessary (for non-root certificates)
func allocateCacheEntries(certificate *x509.Certificate,
	certificateHash string,
	certificateSubjectSKIHash string,
	certificateIssuerAKIHash string) {

	var certificateCacheEntry *CertificateCacheEntry
	certificateCacheEntry = &CertificateCacheEntry{
		certificate:   certificate,
		issuerAKIHash: certificateIssuerAKIHash,
		trustRoot:     false,
	}
	certificateCache[certificateHash] = certificateCacheEntry

	// allocate new subjectSKICache entry or adjust existing entry
	subjectSKICacheEntry, inSubjectSKICache := subjectSKICache[certificateSubjectSKIHash]
	if !inSubjectSKICache {
		subjectSKICacheEntry = newSubjectSKICacheEntry()
		subjectSKICache[certificateSubjectSKIHash] = subjectSKICacheEntry
	}
	subjectSKICache[certificateSubjectSKIHash].certificates[certificateHash] = struct{}{}

	// if the certificate is a leaf, add it to the cache mapping
	// dns names to certificate hashes
	if !certificate.IsCA {
		for _, currentDNSName := range certificate.DNSNames {
			_, inCache := dnsNameCache[currentDNSName]
			if !inCache {
				dnsNameCache[currentDNSName] = []string{}
			}
			dnsNameCache[currentDNSName] = append(dnsNameCache[currentDNSName], certificateHash)
		}
	}
}

// verify child certificate with a (pot.) parent certificate and allocate
// cache entries for the child if necessary
func verifyChildWithParentAndAllocateCaches(certificate *x509.Certificate, parentCertificate *x509.Certificate,
	certificateHash string,
	certificateSubjectSKIHash string,
	certificateIssuerAKIHash string) bool {
	checksPassed, ignore := verifyChildWithParentCertificate(certificate, parentCertificate)

	// if all checks are passed, allocate new cache entries if necessary
	if checksPassed {
		allocateCacheEntries(certificate, certificateHash, certificateSubjectSKIHash, certificateIssuerAKIHash)
		return true
	} else {
		// ignore certificate for future requests if it wasn't added to the cache
		// (e.g., because it was already expired)
		if ignore {
			ignoredCertificateHashes[certificateHash] = struct{}{}
		}
		return false
	}
}

// process a certificate by potentially adding
// it to the cache
// recursively processes parent certificates
// returns the hashes of all processed certificates
func processCertificate(certificate *x509.Certificate,
	certificatesInRequestProcessed map[*x509.Certificate]bool,
	certificatesInRequest map[string][]*x509.Certificate) ([]string, bool) {

	certificateHash := GetRawCertificateHash(certificate)
	processedCertificateHashes := []string{certificateHash}
	certificateSubjectSKIHash := GetRawCertificateSubjectSKIHash(certificate)

	// mark the certificate as processed on exit
	defer func() {
		certificatesInRequestProcessed[certificate] = true
	}()

	// if have already processed the certificate in the request, return whether
	// it was added to the cache
	_, inCache := certificateCache[certificateHash]
	if certificatesInRequestProcessed[certificate] || inCache {
		return processedCertificateHashes, inCache
	}
	_, ignored := ignoredCertificateHashes[certificateHash]
	if ignored {
		return processedCertificateHashes, false
	}

	// remove white-listed unhandled critical extensions
	// (e.g., CT Poison)
	removeWhitelistedUnhandledCriticalExtensions(certificate)

	// if the certificate is self-signed and has the same <Subject, SKI> as a root certificate,
	// add it to the cache
	// TODO: maybe want to be stricter and don't allow this
	ownSubjectSKICacheEntry := subjectSKICache[certificateSubjectSKIHash]
	if certificate.Subject.String() == certificate.Issuer.String() && ownSubjectSKICacheEntry != nil {
		isTrustRoot := false
		for certificateHash, _ := range ownSubjectSKICacheEntry.certificates {
			if certificateCache[certificateHash].trustRoot {
				isTrustRoot = true
			}
		}
		if !isTrustRoot {
			return processedCertificateHashes, false
		}
		// check if currently valid time-wise (hence, treat it as a leaf)
		err := certificate.IsValid(x509.LeafCertificate, []*x509.Certificate{}, &x509.VerifyOptions{})
		if err != nil {
			if ignoreError(err) {
				ignoredCertificateHashes[certificateHash] = struct{}{}
			}
			return processedCertificateHashes, false
		}

		// add the certificate as trust root to both caches
		certificateCacheEntry := &CertificateCacheEntry{
			certificate:   certificate,
			issuerAKIHash: certificateSubjectSKIHash, // self-issued
			trustRoot:     true,
		}
		certificateCacheEntry.certificate = certificate
		certificateCacheEntry.issuerAKIHash = certificateSubjectSKIHash
		certificateCacheEntry.trustRoot = true
		certificateCache[certificateHash] = certificateCacheEntry

		ownSubjectSKICacheEntry.certificates[certificateHash] = struct{}{}
		return processedCertificateHashes, true
	}

	// recursively process parent certificates present in the request
	issuerAKIHash := GetRawCertificateIssuerAKIHash(certificate)
	parentCertificates := certificatesInRequest[issuerAKIHash]
	for _, parentCertificate := range parentCertificates {
		if parentHashes, added := processCertificate(parentCertificate, certificatesInRequestProcessed, certificatesInRequest); added {
			processedCertificateHashes = append(processedCertificateHashes, parentHashes...)
			NCertificatesAdded++
		} else {
			log.Printf("[Go] Did not add certificate with subject: " + certificate.Subject.String() + " " + certificate.Issuer.String() + "\n")
		}
	}

	// now, the cache should be populated with parents (if there were any in the request
	// or already cached)

	// get potential parent certificates of the current certificate
	issuerAKICacheEntry, _ := subjectSKICache[issuerAKIHash]

	// if no potential parent certificate is present in the cache,
	// cannot add the certificate to the cache
	if issuerAKICacheEntry == nil || len(issuerAKICacheEntry.certificates) == 0 {
		return processedCertificateHashes, false
	}

	// check signature

	// get any potential parent certificate (all parent certificates
	// have the same <Subject, public key> so it does not matter)
	var potParentCertificate *x509.Certificate
	for potParentCertHash := range issuerAKICacheEntry.certificates {
		potParentCertificate = certificateCache[potParentCertHash].certificate
		break
	}

	// check that the certificate signature can be verified using the
	// parent certificate and the certificate is currently valid.
	// all other checks on the certificate chain are performed lazily
	// when calling VerifyLegacy
	return processedCertificateHashes, verifyChildWithParentAndAllocateCaches(certificate, potParentCertificate, certificateHash,
		certificateSubjectSKIHash, issuerAKIHash)
}

// adds a list of certificates to the cache
// TODO: pot. hashing the certificates is unnecessary as the hashes might already
// be available from the first mapserver response
func AddCertificatesToCache(certificates []*x509.Certificate) []string {

	nEntriesBefore := len(certificateCache)
	now := time.Now()

	// create a map of all certificates in the request, indicating whether
	// the certificate has already been processed
	certificatesInRequestProcessed := map[*x509.Certificate]bool{}
	// create a set of all hashes of <Subject, SubjectKeyId> in the request
	certificatesInRequest := map[string][]*x509.Certificate{}
	for _, certificate := range certificates {
		certificatesInRequestProcessed[certificate] = false
		certificateSubjectSKIHash := GetRawCertificateSubjectSKIHash(certificate)
		v := certificatesInRequest[certificateSubjectSKIHash]
		if v == nil {
			certificatesInRequest[certificateSubjectSKIHash] = []*x509.Certificate{}
		}
		certificatesInRequest[certificateSubjectSKIHash] = append(certificatesInRequest[certificateSubjectSKIHash], certificate)
	}
	// add all certificates to cache
	// skip certificates that have already been added
	// in a recursive step
	var processedCertificateHashes []string
	for _, certificate := range certificates {
		if !certificatesInRequestProcessed[certificate] {
			hashes, added := processCertificate(certificate, certificatesInRequestProcessed, certificatesInRequest)
			processedCertificateHashes = append(processedCertificateHashes, hashes...)
			if added {
				NCertificatesAdded++
			} else {
				fmt.Printf("[Go] Did not add certificate with subject: " + certificate.Subject.String() + " " + certificate.Issuer.String() + "\n")
			}
		}
	}
	MS = MS + time.Now().Sub(now).Milliseconds()
	fmt.Printf("[Go] Added %d certificates to cache\n", len(certificateCache)-nEntriesBefore)
	fmt.Printf("[Go] Total # cache entries: %d\n", len(certificateCache))
	fmt.Printf("[Go] Time spent checking signatures: %d ms\n ", MSS)

	MS = 0
	NCertificatesAdded = int64(len(certificateCache) - nEntriesBefore)

	return processedCertificateHashes
}

// helper function to recursively build certificate chains
func buildChains(certificateHash string) []*CertificateChainInfo {
	certificateCacheEntry, _ := certificateCache[certificateHash]
	if certificateCacheEntry.trustRoot {
		// base case: reached a root certificate
		l := []*x509.Certificate{certificateCacheEntry.certificate}
		certificateChainInfo := &CertificateChainInfo{certificateChain: l, constraintsApply: false}
		certificateChainInfo.constraintsApply = checkIfConstraintsApply(certificateCacheEntry.certificate)
		return []*CertificateChainInfo{certificateChainInfo}
	} else {
		// step case: recursively build certificate chain
		certificateCacheEntry, _ := certificateCache[certificateHash]
		var l []*CertificateChainInfo
		for parentCertificateHash, _ := range subjectSKICache[certificateCacheEntry.issuerAKIHash].certificates {
			chains := buildChains(parentCertificateHash)
			for _, chain := range chains {
				ll := append([]*x509.Certificate{certificateCacheEntry.certificate}, chain.certificateChain...)
				certificateChainInfo := &CertificateChainInfo{certificateChain: ll, constraintsApply: false}
				if chain.constraintsApply {
					certificateChainInfo.constraintsApply = true
				} else {
					certificateChainInfo.constraintsApply = checkIfConstraintsApply(certificateCacheEntry.certificate)
				}
				l = append(l, certificateChainInfo)
			}
		}
		return l
	}
}

// returns all the certificate chains in the cache for a specific dns name
func GetCertificateChainsForDomain(dnsName string) []*CertificateChainInfo {

	// query with full dnsName and dnsName with last subdomain replaced as a wildcard
	dnsNames := []string{dnsName}
	split := strings.Split(dnsName, ".")
	if len(split) >= 2 {
		split[0] = "*"
		dnsNames = append(dnsNames, strings.Join(split, "."))
	}
	var chains []*CertificateChainInfo
	for _, currentDNSName := range dnsNames {
		certificateHashes, inCache := dnsNameCache[currentDNSName]
		if !inCache {
			continue
		} else {
			for _, certificateHash := range certificateHashes {
				currentChains := buildChains(certificateHash)
				chains = append(chains, currentChains...)
			}
		}
	}
	return chains
}
