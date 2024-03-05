package cache_v2

import (
	"crypto/x509"
	"strings"
	"time"
)

type LegacyTrustPreference struct {

	// CA set identifier
	CASetIdentifier string

	// set of CA subject names
	// TODO: probably also want to include the public key of the CA
	CASubjectNames map[string]struct{}

	// map CA set to TrustLevel
	TrustLevel int
}

type LegacyTrustInfo struct {
	// domain name used in the connection
	DNSName string

	// certificate chain received during the connection establishment
	CertificateChain []*x509.Certificate

	// the trust level of the connection certificate chain based
	// on the client's legacy trust preference, with examples
	// of the CA set ID's and subject that led to this trust level
	// (might be useful to construct error messages)
	ConnectionTrustLevel           int
	ConnectionTrustLevelCASet      string
	ConnectionTrustLevelChainIndex int

	// CA set ID's and example subjects, and trust level of the
	// cached certificate chains that led to a failed
	// validation
	// (might be useful to construct error messages)
	HighestTrustLevel              int `default:"0"`
	HighestTrustLevelCASets        []string
	HighestTrustLevelChainIndices  []int
	HighestTrustLevelChainHashes   [][]string
	HighestTrustLevelChainSubjects [][]string

	// result of legacy validation
	// a value of 1 indicates that validation
	// was passed.
	// a value != 1 indicates failed validation
	EvaluationResult int `default:"0"`

	// timestamp indicating how long this
	// legacy validation outcome can be cached
	MaxValidity time.Time
}

// maps a domain name to a set of legacy trust preferences
// to be used to compute certificate chain trust levels
var legacyTrustPreferences = map[string][]*LegacyTrustPreference{}

// initialize legacyTrustPreferences  with a config
func InitializeLegacyTrustPreferences(configMap map[string]interface{}) {

	// parse CA sets
	caSetsMap := map[string][]string{}
	caSets := configMap["ca-sets"].(map[string]interface{})
	for ca, values := range caSets {
		caSetsMap[ca] = []string{}
		v := values.(map[string]interface{})
		for _, value := range v["cas"].([]interface{}) {
			caSetsMap[ca] = append(caSetsMap[ca], value.(string))
		}
	}

	// get trust level map
	trustLevelMap := configMap["trust-levels"].(map[string]interface{})

	// parse legacy trust preferences
	legacyTrustPreferencesJSON := configMap["legacy-trust-preference"].(map[string]interface{})
	for domain, keys := range legacyTrustPreferencesJSON {
		domainTrustPreferences := []*LegacyTrustPreference{}
		objects := keys.([]interface{})
		for _, object := range objects {
			objectMap := object.(map[string]interface{})
			caSetStr := objectMap["ca-set"].(string)
			trustLevel := int(trustLevelMap[objectMap["level"].(string)].(float64))
			caSubjectNames := map[string]struct{}{}
			for _, caSubjectName := range caSetsMap[caSetStr] {
				caSubjectNames[caSubjectName] = struct{}{}
			}
			legacyTrustPreference := &LegacyTrustPreference{
				CASetIdentifier: caSetStr,
				CASubjectNames:  caSubjectNames,
				TrustLevel:      trustLevel,
			}
			domainTrustPreferences = append(domainTrustPreferences, legacyTrustPreference)
		}
		legacyTrustPreferences[domain] = domainTrustPreferences
	}
}

// compute the trust level of a single certificate for a domain (dnsName)
func ComputeSingleCertificateTrustLevelForDomain(dnsName string, certificate *x509.Certificate) int {
	trustLevel := 0
	legacyTrustPreferencesForDomain, hasTrustPreference := legacyTrustPreferences[dnsName]

	// if there are no legacy trust preferences for the domain,
	// the default trust level is 0
	if !hasTrustPreference {
		return trustLevel
	}

	// check if the certificate's subject is mentioned in the legacy trust preference
	// NOTE: likely, legacy trust preferences won't contain only the subject,
	// but also a public key hash
	for _, legacyTrustPreference := range legacyTrustPreferencesForDomain {
		_, subjectInLegacyTrustPreference := legacyTrustPreference.CASubjectNames[certificate.Subject.String()]
		if subjectInLegacyTrustPreference && legacyTrustPreference.TrustLevel > trustLevel {
			trustLevel = legacyTrustPreference.TrustLevel
		}
	}
	return trustLevel
}

func generateWildcardAndParentDomain(dnsName string) []string {
	dnsNameNormalized := strings.TrimSuffix(dnsName, ".")
	components := strings.Split(dnsNameNormalized, ".")
	orderedParentDomains := make([]string, 2*len(components))
	for from := range components {
		orderedParentDomains = append(orderedParentDomains, strings.Join(components[from:], "."))
		orderedParentDomains = append(orderedParentDomains, strings.Join(append([]string{"*"}, components[from+1:]...), "."))
	}
	return orderedParentDomains
}

// compute the trust level of a certificate chain for a given
// domain name (dnsName)
// also returns the subject and CA Set ID of a root CA that led to this specific trust level and the domain for which the trust preference was set
func ComputeChainTrustLevelForDomainAndParents(dnsName string, certificateChain []*x509.Certificate) (int, string, int, string) {
	var trustLevel int
	var relevantCASetID string
	var relevantCertificateChainIndex int
	var relevantDomain string

	for idx, domain := range generateWildcardAndParentDomain(dnsName) {
		currentTrustLevel, currentRelevantCASetID, currentRelevantCertificateChainIndex := ComputeChainTrustLevelForDomain(domain, certificateChain)
		if idx == 0 || currentTrustLevel > trustLevel {
			trustLevel = currentTrustLevel
			relevantCASetID = currentRelevantCASetID
			relevantCertificateChainIndex = currentRelevantCertificateChainIndex
			relevantDomain = domain
		}
	}

	return trustLevel, relevantCASetID, relevantCertificateChainIndex, relevantDomain
}

// compute the trust level of a certificate chain for a given
// (wildcard) domain name or (dnsName)
// also returns the subject and CA Set ID of a root CA that led to this specific trust level
func ComputeChainTrustLevelForDomain(dnsName string, certificateChain []*x509.Certificate) (int, string, int) {
	currentTrustLevel := 0
	relevantCertificateChainIndex := 0
	relevantCASetID := "DEFAULT"

	// if there are no legacy trust preferences for the domain,
	// the default trust level is 0
	legacyTrustPreferencesForDomain, hasTrustPreference := legacyTrustPreferences[dnsName]
	if !hasTrustPreference {
		return currentTrustLevel, relevantCASetID, relevantCertificateChainIndex
	}
	// iterate through all non-leaf certificates of the chain and determine
	// the trust level by taking the maximum trust level of each individual certificate
	// Since the preferences for a specific domain are applied using a first-match approach, we must iterate through the preferences in order
	for _, legacyTrustPreference := range legacyTrustPreferencesForDomain {
		for index, certificate := range certificateChain[1:] {
			_, subjectInLegacyTrustPreference := legacyTrustPreference.CASubjectNames[certificate.Subject.String()]
			if subjectInLegacyTrustPreference && legacyTrustPreference.TrustLevel > currentTrustLevel {
				currentTrustLevel = legacyTrustPreference.TrustLevel
				relevantCASetID = legacyTrustPreference.CASetIdentifier
				// increment the index since we skip the leaf certificate
				relevantCertificateChainIndex = index + 1
			}
		}
	}
	return currentTrustLevel, relevantCASetID, relevantCertificateChainIndex
}

// get certificate chains with highest trust level from a list of certificate chains
// also check for how long the legacy validation result based on this set
// of certificates can be cached
func GetHighestTrustLevelCertificateChains(dnsName string, certificateChains []*CertificateChainInfo) ([]*CertificateChainInfo, int, []string, []int, [][]string, [][]string, time.Time) {
	// for each certiicate chain with the highest trust level, also
	// store why they have this trust level (CA Set ID, and an example subject).
	// this information is used to create error messages if necessary
	highestTrustCertificateChains := []*CertificateChainInfo{}
	var relevantCertificateChainIndices []int
	var relevantCASetIDs []string
	var chainCertificateHashes [][]string
	var chainCertificateSubjects [][]string

	// determine how long the set of certificate chains with highest
	// trust level should be cached.
	// currently it is valid for 10 minutes, except some chain's
	// leaf certificate expires sooner
	var minNotAfterTsd = time.Now().Add(10 * time.Minute)
	highestTrustLevel := 0
	// only consider the certificate chains with the highest trust level
	for _, certificateChainInfo := range certificateChains {
		currentTrustLevel, relevantCASetID, relevantCertificateChainIndex, _ := ComputeChainTrustLevelForDomainAndParents(dnsName, certificateChainInfo.certificateChain)
		if currentTrustLevel > highestTrustLevel {
			highestTrustCertificateChains = []*CertificateChainInfo{certificateChainInfo}
			relevantCASetIDs = []string{relevantCASetID}
			relevantCertificateChainIndices = []int{relevantCertificateChainIndex}

			var currentSubjects []string
			for _, cert := range certificateChainInfo.certificateChain {
				currentSubjects = append(currentSubjects, cert.Subject.String())
			}
			chainCertificateSubjects = [][]string{currentSubjects}

			var currentHashes []string
			for _, cert := range certificateChainInfo.certificateChain {
				currentHashes = append(currentHashes, GetRawCertificateHash(cert))
			}
			chainCertificateHashes = [][]string{currentHashes}

			highestTrustLevel = currentTrustLevel
			notAfter := certificateChainInfo.certificateChain[0].NotAfter
			if notAfter.Before(minNotAfterTsd) {
				minNotAfterTsd = notAfter
			}
		} else if currentTrustLevel == highestTrustLevel {
			highestTrustCertificateChains = append(highestTrustCertificateChains, certificateChainInfo)
			relevantCASetIDs = append(relevantCASetIDs, relevantCASetID)
			relevantCertificateChainIndices = append(relevantCertificateChainIndices, relevantCertificateChainIndex)

			var currentSubjects []string
			for _, cert := range certificateChainInfo.certificateChain {
				currentSubjects = append(currentSubjects, cert.Subject.String())
			}
			chainCertificateSubjects = append(chainCertificateSubjects, currentSubjects)

			var currentHashes []string
			for _, cert := range certificateChainInfo.certificateChain {
				currentHashes = append(currentHashes, GetRawCertificateHash(cert))
			}
			chainCertificateHashes = append(chainCertificateHashes, currentHashes)

			notAfter := certificateChainInfo.certificateChain[0].NotAfter
			if notAfter.Before(minNotAfterTsd) {
				minNotAfterTsd = notAfter
			}
		}
	}
	return highestTrustCertificateChains, highestTrustLevel, relevantCASetIDs, relevantCertificateChainIndices, chainCertificateHashes, chainCertificateSubjects, minNotAfterTsd
}

// check if a certificate contains constraints that must be checked in case
// legacy validation fails the first time (legacy validation might have
// failed due to invalid certificate chains that need to be filtered out)
func checkIfConstraintsApply(c *x509.Certificate) bool {

	if c.BasicConstraintsValid && c.IsCA && (c.MaxPathLen > 0 || (c.MaxPathLenZero && c.MaxPathLen != 0)) ||
		(len(c.PermittedDNSDomains) > 0 ||
			len(c.ExcludedDNSDomains) > 0 ||
			len(c.PermittedIPRanges) > 0 ||
			len(c.ExcludedIPRanges) > 0 ||
			len(c.PermittedEmailAddresses) > 0 ||
			len(c.ExcludedEmailAddresses) > 0 ||
			len(c.PermittedURIDomains) > 0 ||
			len(c.ExcludedURIDomains) > 0) {
		return true
	}
	return false
}

// check if a certificate chain satisfies its constraints by checking them
// for each certificate
func checkIfConstraintsSatisfied(certificateChain []*x509.Certificate) error {

	// check leaf
	leaf := certificateChain[0]
	verifyOpts := &x509.VerifyOptions{}
	err := leaf.IsValid(x509.LeafCertificate, []*x509.Certificate{}, verifyOpts)
	if err != nil {
		return err
	}

	// check intermediates
	for i := 1; i < len(certificateChain)-1; i++ {
		err = certificateChain[i].IsValid(x509.IntermediateCertificate, certificateChain[:i], verifyOpts)
		if err != nil {
			return err
		}
	}

	// check root
	root := certificateChain[len(certificateChain)-1]
	err = root.IsValid(x509.RootCertificate, certificateChain[:len(certificateChain)-1], verifyOpts)
	if err != nil {
		return err
	}
	return nil
}

// check if <Subject, SKI> of certificate matches a leaf certificate of a valid chain in certificateChains
func checkSubjectSKI(certificate *x509.Certificate, certificateChains []*CertificateChainInfo) bool {
	certificateSubjectSKIHash := GetRawCertificateSubjectSKIHash(certificate)
	for _, certificateChainInfo := range certificateChains {
		currentLeafSubjectSKIHash := GetRawCertificateSubjectSKIHash(certificateChainInfo.certificateChain[0])
		if certificateSubjectSKIHash == currentLeafSubjectSKIHash {
			if certificateChainInfo.constraintsApply {

				// check if the certificate chain is valid
				keyUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
				if !x509.CheckChainForKeyUsage(certificateChainInfo.certificateChain, keyUsages) {
					return false
				}
				err := checkIfConstraintsSatisfied(certificateChainInfo.certificateChain)
				if err != nil {
					return false
				}
				return true
			} else {
				return true
			}
		}
	}
	return false
}

// a lower trust level of the connection might be acceptable
// in some cases (e.g., when the public key matches a
// certificate with a higher trust level)
func checkIfLowerTrustLevelAllowed(connectionChain []*x509.Certificate, cachedCertificateChains []*CertificateChainInfo) bool {
	return checkSubjectSKI(connectionChain[0], cachedCertificateChains)
}

// perform legacy validation of the certificate chain received in the  connection establishment
// against a (potentially pruned) set of certificate chains
func verifyLegacyAgainstChains(connectionTrustInfoToVerify *LegacyTrustInfo, certificateChains []*CertificateChainInfo) {
	connectionTrustLevel := connectionTrustInfoToVerify.ConnectionTrustLevel

	// get all cached certificate chains with the highest trust level
	highestTrustLevelCertificateChainsCached, highestTrustLevelCached, relevantCASetIDs, relevantCertificateChainIndices, chainCertificateHashes, chainCertificateSubjects, minNotAfterTsd := GetHighestTrustLevelCertificateChains(connectionTrustInfoToVerify.DNSName,
		certificateChains)

	// if the connection certificate chain has a lower trust level as some cached
	// certificate chains, we might still accept it.
	// Namely, if the connection leaf certificate has the same <Subject, SKI>
	// as the leaf of a cached certificate chain with highest trust level.
	if connectionTrustLevel < highestTrustLevelCached {
		checksPassed := checkIfLowerTrustLevelAllowed(connectionTrustInfoToVerify.CertificateChain, highestTrustLevelCertificateChainsCached)
		if checksPassed {
			connectionTrustInfoToVerify.EvaluationResult = SUCCESS
		} else {
			connectionTrustInfoToVerify.EvaluationResult = FAILURE
			connectionTrustInfoToVerify.HighestTrustLevelCASets = relevantCASetIDs
			connectionTrustInfoToVerify.HighestTrustLevelChainIndices = relevantCertificateChainIndices
			connectionTrustInfoToVerify.HighestTrustLevelChainHashes = chainCertificateHashes
			connectionTrustInfoToVerify.HighestTrustLevelChainSubjects = chainCertificateSubjects
			connectionTrustInfoToVerify.HighestTrustLevel = highestTrustLevelCached
		}
	} else {
		connectionTrustInfoToVerify.EvaluationResult = SUCCESS
	}
	connectionTrustInfoToVerify.MaxValidity = minNotAfterTsd
}

// Evaluate whether connection should be allowed according to
// legacy mode based on current state of the cache.
// This algorithm uses lazy evaluation (i.e., it first
// attempts to verify the connection using all cached certificate chains,
// and if this fails, it filters out the invalid certificate chains and
// attempts to verify the connection again).
func VerifyLegacy(connectionTrustInfoToVerify *LegacyTrustInfo) {
	certificateChains := GetCertificateChainsForDomain(connectionTrustInfoToVerify.DNSName)
	verifyLegacyAgainstChains(connectionTrustInfoToVerify, certificateChains)
	if connectionTrustInfoToVerify.EvaluationResult == FAILURE {
		// certificate chains that do not satisfy constraints (e.g., extended key usages, name constraints)
		// and therefore are invalid potentially prevent a successful verification.
		// => prune these chains and retry
		var certificateChainsPruned []*CertificateChainInfo
		removedChains := false
		keyUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		for _, certificateChainInfo := range certificateChains {

			// check key usage of the certificate chain
			if !x509.CheckChainForKeyUsage(certificateChainInfo.certificateChain, keyUsages) {
				removedChains = true
				continue
			}

			// if the certificate chain has constraints that pot. invalidate the
			// certificate chain, check that they hold and otherwise remove
			// the certificate chain
			if certificateChainInfo.constraintsApply {
				err := checkIfConstraintsSatisfied(certificateChainInfo.certificateChain)
				if err == nil {
					certificateChainsPruned = append(certificateChainsPruned, certificateChainInfo)
				} else {
					removedChains = true
				}
			} else {
				certificateChainsPruned = append(certificateChainsPruned, certificateChainInfo)
			}
		}

		// if some certificate chains were pruned, retry legacy validation
		// using only the valid certificate chains
		if removedChains {
			verifyLegacyAgainstChains(connectionTrustInfoToVerify, certificateChainsPruned)
		}
	}
}

// create new LegacyTrustInfo and initialize trustLevel by
// computing it for the provided certificateChain
func NewLegacyTrustInfo(dnsName string, certificateChain []*x509.Certificate) *LegacyTrustInfo {
	legacyTrustInfo := &LegacyTrustInfo{
		DNSName:              dnsName,
		CertificateChain:     certificateChain,
		ConnectionTrustLevel: 0,
		EvaluationResult:     0,
	}

	trustLevel, relevantCASetID, relevantCertificateChainIndex, _ := ComputeChainTrustLevelForDomainAndParents(dnsName, certificateChain)
	legacyTrustInfo.ConnectionTrustLevel = trustLevel
	legacyTrustInfo.ConnectionTrustLevelCASet = relevantCASetID
	legacyTrustInfo.ConnectionTrustLevelChainIndex = relevantCertificateChainIndex
	return legacyTrustInfo
}
