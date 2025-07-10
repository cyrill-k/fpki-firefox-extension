package cache_v2

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"golang.org/x/net/publicsuffix"
)

// create new PolicyTrustInfo
func NewPolicyTrustInfo(dnsName string, certificateChain []*x509.Certificate) *PolicyTrustInfo {
	policyTrustInfo := &PolicyTrustInfo{
		DNSName:                     dnsName,
		CertificateChain:            certificateChain,
		PolicyChain:                 nil,
		ConflictingPolicyAttributes: nil,
		PolicyChainTrustLevel:       0,
		EvaluationResult:            0,
		MaxValidity:                 time.Unix(0, 0),
		DomainExcluded:              false,
	}
	return policyTrustInfo
}

func NewDomainPolicyTrustPreferences() DomainPolicyTrustPreferences {
	return DomainPolicyTrustPreferences{
		PublicKeyTrustLevelMap: map[string]int{},
	}
}

type DomainPolicyTrustPreferences struct {
	PublicKeyTrustLevelMap map[string]int

	// TODO: also implement setting the trust preferences for specific policy certificate specified via their immutable hash
	// ImmutableHashTrustLevelMap map[string]int
}

type ConflictingPolicyAttribute struct {
	Domain    string
	Attribute *common.PolicyAttributes
}

type PolicyTrustInfo struct {
	// domain name used in the connection
	DNSName string

	// certificate chain received during the connection establishment
	CertificateChain []*x509.Certificate

	// CA set ID's and example subjects, and trust level of the
	// cached certificate chains that led to a failed
	// validation
	// (might be useful to construct error messages)

	// json encoded policy certifcates
	PolicyChain                 []*common.PolicyCertificate
	ConflictingPolicyAttributes []*ConflictingPolicyAttribute
	PolicyChainTrustLevel       int `default:"0"`

	// result of legacy validation
	// a value of 1 indicates that validation
	// was passed.
	// a value != 1 indicates failed validation
	EvaluationResult int `default:"0"`

	// timestamp indicating how long this
	// legacy validation outcome can be cached
	MaxValidity time.Time

	// true if the most specific policy (i.e., highest number of subdomains) added DNSName (or a
	// parent of DNSName) as an excluded subdomain where no policy attributes are applied
	DomainExcluded bool
}

// maps a domain name to a set of policy trust preferences to be used to compute policy certificate
// chain trust levels
var policyTrustPreferences = map[string]DomainPolicyTrustPreferences{}

type PolicyCertificateChain struct {
	PolicyCertificates                       []*common.PolicyCertificate
	DomainRootIssuanceTimestamp              time.Time
	DomainRootMinMaxTimestamp                time.Time
	RootAndIntermediateLatestMinMaxTimestamp time.Time
	DomainLatestMinMaxTimestamp              time.Time
	TrustLevel                               int

	// DisseminationTime  time.Time
}

// returns true if the first certificate of the policy chain is the domain root certificate for the
// provided rootDomain
func (pcChain *PolicyCertificateChain) StartsWithDomainRootCertificate(rootDomain string) bool {
	// if the first policy certificate is issued for the root domain and
	if pcChain.PolicyCertificates[0].Domain() == rootDomain {
		// if this certificate is self-signed, or
		if len(pcChain.PolicyCertificates) == 1 {
			return true
		}

		// if the parent certificate is issued over a different domain (an ancestor domain)
		if pcChain.PolicyCertificates[1].Domain() != rootDomain {
			return true
		}
	}
	return false
}

func (pcChain PolicyCertificateChain) String() string {
	str := fmt.Sprintf("<PolicyCertificateChain len=%d", len(pcChain.PolicyCertificates))
	str += fmt.Sprintf(", DomainRootIssuanceTimestamp=%v", pcChain.DomainRootIssuanceTimestamp)
	str += fmt.Sprintf(", DomainRootMinMaxTimestamp=%v", pcChain.DomainRootMinMaxTimestamp)
	str += fmt.Sprintf(", RootAndIntermediateLatestMinMaxTimestamp=%v", pcChain.RootAndIntermediateLatestMinMaxTimestamp)
	str += ", certs="
	for _, pc := range pcChain.PolicyCertificates {
		if pc == nil {
			str += "nil, "
			continue
		}
		attributes, err := json.Marshal(pc.PolicyAttributes)
		if err != nil {
			break
		}
		pcStr := fmt.Sprintf("<Policy domain=%s, attributes=%s, #SPCTs=%d, hash=%s, immHash=%s >", pc.Domain(), attributes, len(pc.SPCTs), getPolicyHash(pc), getImmutablePolicyHash(pc))
		// pcStr, err := common.ToJSON(pc)
		// if err != nil {
		// break
		// }
		str += fmt.Sprintf("%s, ", pcStr)
	}
	return str + ">"
}

func NewPolicyCertificateChain() *PolicyCertificateChain {
	return &PolicyCertificateChain{
		PolicyCertificates:                       []*common.PolicyCertificate{},
		DomainRootIssuanceTimestamp:              time.Unix(0, 0),
		DomainRootMinMaxTimestamp:                time.Unix(0, 0),
		RootAndIntermediateLatestMinMaxTimestamp: time.Unix(0, 0),
		DomainLatestMinMaxTimestamp:              time.Unix(0, 0),
		TrustLevel:                               0,
	}
}

// initialize legacyTrustPreferences with a config
func InitializePolicyTrustPreferences(configMap map[string]interface{}) {
	policyTrustPreferences = map[string]DomainPolicyTrustPreferences{}

	// parse policy CA sets
	pcaSetsMap := map[string][]string{}
	pcaSets := configMap["policy-ca-sets"].(map[string]interface{})
	for pcaSetID, values := range pcaSets {
		pcaSetsMap[pcaSetID] = []string{}
		v := values.(map[string]interface{})
		for _, value := range v["pcas"].([]interface{}) {
			pcaSetsMap[pcaSetID] = append(pcaSetsMap[pcaSetID], value.(string))
		}
	}

	// parse policy CAs
	pcasPublicKeyMap := map[string]string{}
	pcas := configMap["policy-cas"].(map[string]interface{})
	for pcaID, values := range pcas {
		v := values.(map[string]interface{})
		pcasPublicKeyMap[pcaID] = v["publickey"].(string)
	}

	// get trust level map
	trustLevelMap := configMap["trust-levels"].(map[string]interface{})

	// parse policy trust preferences
	policyTrustPreferencesJSON := configMap["policy-trust-preference"].(map[string]interface{})
	for domain, entry := range policyTrustPreferencesJSON {
		domainTrustPreferences := NewDomainPolicyTrustPreferences()
		objects := entry.([]interface{})
		for _, object := range objects {
			objectMap := object.(map[string]interface{})
			trustLevel := int(trustLevelMap[objectMap["level"].(string)].(float64))
			pcaSetID := objectMap["policy-ca-set"].(string)
			for _, pca := range pcaSetsMap[pcaSetID] {
				domainTrustPreferences.PublicKeyTrustLevelMap[pcasPublicKeyMap[pca]] = trustLevel
			}
		}
		policyTrustPreferences[domain] = domainTrustPreferences
	}
}

// determines the highest trust level of a policy certificate according to the policy trust
// preference
//
// returns 0 if no trust level can be assigned based on the trust preference
func getPolicyCertificateTrustLevel(cert *common.PolicyCertificate) int {
	base64PublicKey := base64.StdEncoding.EncodeToString(cert.PublicKey)

	domains := generateWildcardAndParentDomain(cert.Domain())
	highestTrustLevel := 0
	for _, domain := range domains {
		if trustLevel, ok := policyTrustPreferences[domain].PublicKeyTrustLevelMap[base64PublicKey]; ok {
			highestTrustLevel = trustLevel
		}
	}

	return highestTrustLevel
}

// find the policy certificate chain which has the latest max timestamp in the set [issuance, SPCT time 1, SPCT time 2, ...].
// The second parameter is an optional root chain (e.g., domain root cert to root cert) that must be used. If nil is passed as an argument, any chain is accepted. If no acceptable chain can be generated, nil is returned.
func getPolicyCertificateChainWithLatestTimestamp(immutableHash string, rootDomain string, rootChain *PolicyCertificateChain) (*PolicyCertificateChain, error) {

	if rootChain != nil {
		if immutableHash == getImmutablePolicyHash(rootChain.PolicyCertificates[0]) {
			return rootChain, nil
		}
	} else {
		if immutableHash == base64.StdEncoding.EncodeToString(nil) {
			return NewPolicyCertificateChain(), nil
		}
	}

	issuerEntry, ok := immutablePolicyCache[immutableHash]
	if !ok {
		return nil, fmt.Errorf("Inconsistent caches: policy with immutable hash %s does not exist", immutableHash)
	}
	parentChain, err := getPolicyCertificateChainWithLatestTimestamp(issuerEntry.immutableIssuerHash, rootDomain, rootChain)
	if err != nil {
		return nil, err
	}
	if parentChain == nil {
		return nil, nil
	}

	// find certificate with latest hash
	// select first certificate with the given immutable hash
	if len(issuerEntry.policyHashes) == 0 {
		return nil, fmt.Errorf("Inconsistent caches: no policy certificate corresponding to immutable hash %s exists", immutableHash)
	}
	var minMaxTimestampPcEntry *common.PolicyCertificate
	var minMaxTimestamp time.Time
	for i, hash := range issuerEntry.policyHashes {
		pcEntry, ok := policyCache[hash]
		if !ok {
			return nil, fmt.Errorf("Inconsistent caches: policy with hash %s does not exist", hash)
		}
		tLatest := pcEntry.policy.TimeStamp
		for _, spct := range pcEntry.policy.SPCTs {
			tLatest = maxTime(tLatest, spct.AddedTS)
		}
		if i == 0 || tLatest.Before(minMaxTimestamp) {
			minMaxTimestamp = tLatest
			minMaxTimestampPcEntry = pcEntry.policy
		}
	}

	// check if the current cert is domain root certificate, i.e., the policy certificate issued for
	// the root domain that is closest to the policy root store certificate. Note that the domain
	// root certificate may itself be in the policy root store.
	isDomainRootCertificate := minMaxTimestampPcEntry.Domain() == rootDomain && (len(parentChain.PolicyCertificates) == 0 || parentChain.PolicyCertificates[0].Domain() != rootDomain)

	// check if the current cert is an ancestor to the domain root certificate
	isDomainRootCertificateParent := len(minMaxTimestampPcEntry.Domain()) < len(rootDomain)

	domainRootIssuanceTimestamp := parentChain.DomainRootIssuanceTimestamp
	if isDomainRootCertificate {
		domainRootIssuanceTimestamp = minMaxTimestampPcEntry.TimeStamp
	}
	domainRootMinMaxTimestamp := parentChain.DomainRootMinMaxTimestamp
	if isDomainRootCertificate {
		domainRootMinMaxTimestamp = minMaxTimestamp
	}
	rootAndIntermediateLatestMinMaxTimestamp := parentChain.RootAndIntermediateLatestMinMaxTimestamp
	if isDomainRootCertificateParent {
		rootAndIntermediateLatestMinMaxTimestamp = maxTime(rootAndIntermediateLatestMinMaxTimestamp, minMaxTimestamp)
	}
	domainLatestMinMaxTimestamp := parentChain.DomainLatestMinMaxTimestamp
	if !isDomainRootCertificate && !isDomainRootCertificateParent {
		domainLatestMinMaxTimestamp = maxTime(domainLatestMinMaxTimestamp, minMaxTimestamp)
	}

	// The trust level of the chain is the maximum trust level of any certificate in the chain
	// according to the policy trust preference. Since trust levels are assigned via a certificate's
	// public key, we must ensure that the creator of the policy certificate knows the corresponding
	// private key. Otherwise, an adversary can create a leaf certificate with an arbitrary policy
	// and include a public key associated with a high trust level to convince the relying party to
	// accept this policy.
	var pcTrustLevel int
	if immutableHash == base64.StdEncoding.EncodeToString(nil) {
		// the signature of the self-signed policy certificate with its own private key is verified
		// when the certificate is added to the policy cache
		pcTrustLevel = getPolicyCertificateTrustLevel(minMaxTimestampPcEntry)
	}
	var parentPcTrustLevel int
	if len(parentChain.PolicyCertificates) > 0 {
		// the signature of a child policy certificate with the parent's private key is verified
		// when the child certificate is added to the policy cache
		parentPcTrustLevel = getPolicyCertificateTrustLevel(parentChain.PolicyCertificates[0])
	}
	// the final trust level is the highest trust level of this certificate, the parent certificate,
	// and the chain leading to up to the root policy certificate
	trustLevel := max(parentChain.TrustLevel, pcTrustLevel, parentPcTrustLevel)

	return &PolicyCertificateChain{
		PolicyCertificates:                       append([]*common.PolicyCertificate{minMaxTimestampPcEntry}, parentChain.PolicyCertificates...),
		DomainRootIssuanceTimestamp:              domainRootIssuanceTimestamp,
		DomainRootMinMaxTimestamp:                domainRootMinMaxTimestamp,
		RootAndIntermediateLatestMinMaxTimestamp: rootAndIntermediateLatestMinMaxTimestamp,
		DomainLatestMinMaxTimestamp:              domainLatestMinMaxTimestamp,
		TrustLevel:                               trustLevel,
	}, nil
}

func findPolicyCertificateChainsForE2LD(domain string) ([]*PolicyCertificateChain, error) {
	leafHashes, ok := policyDnsNameCache[domain]
	if !ok {
		return nil, nil
	}

	chains := []*PolicyCertificateChain{}
	for _, leafHash := range leafHashes {
		leafCacheEntry, ok := policyCache[leafHash]
		if !ok {
			return nil, fmt.Errorf("Inconsistent caches: policy with hash %s does not exist", leafHash)
		}
		chain, err := getPolicyCertificateChainWithLatestTimestamp(leafCacheEntry.immutableHash, domain, nil)
		if err != nil {
			return chains, fmt.Errorf("Failed to get policy cert chain with latest timestamp: %s", err)
		}
		// only consider chains that start with a policy certificate for the root domain, i.e., chain [Policy("example.com"), Policy("example.com"), Policy("com"), Policy("")] would be discarded
		if chain.StartsWithDomainRootCertificate(domain) {
			chains = append(chains, chain)
		}
	}
	return chains, nil
}

// returns all policy certificate chains that are currently valid, i.e., chains where the following
// invariant holds for the leaf certificate: NotBefore <= currentTime <= NotAfter
//
// Note that the validity periods of all parent certificate is guaranteed to be a superset of the
// validity period of the leaf certificate
func removeInvalidPolicyCertificateChains(policyCertificateChains []*PolicyCertificateChain, currentTime time.Time) (validChains []*PolicyCertificateChain) {
	for _, chain := range policyCertificateChains {
		leafCert := chain.PolicyCertificates[0]
		if currentTime.Before(leafCert.NotBefore) {
			continue
		}
		if currentTime.After(leafCert.NotAfter) {
			continue
		}
		validChains = append(validChains, chain)
	}
	return validChains
}

func filterHighestTrustLevelPolicyCertificateChains(policyCertificateChains []*PolicyCertificateChain) (highestTrustLevelChains []*PolicyCertificateChain) {
	highestTrustLevel := 0
	// find the highest trust level
	for _, chain := range policyCertificateChains {
		if chain.TrustLevel > highestTrustLevel {
			highestTrustLevel = chain.TrustLevel
		}
	}
	// filter out chains with a lower trust level
	for _, chain := range policyCertificateChains {
		if chain.TrustLevel < highestTrustLevel {
			continue
		}
		highestTrustLevelChains = append(highestTrustLevelChains, chain)
	}
	return highestTrustLevelChains
}

func findPolicyCertificateChainForDomain(domain string, domainRootPolicyCertificateChain *PolicyCertificateChain) (*PolicyCertificateChain, error) {
	e2ld := domainRootPolicyCertificateChain.PolicyCertificates[0].Domain()
	subdomainsString, found := strings.CutSuffix(domain, e2ld)
	if !found {
		return nil, fmt.Errorf("Domain is not a subdomain of e2ld")
	}
	subdomains := strings.Split(subdomainsString, ".")

	currentDomain := e2ld
	var finalChain *PolicyCertificateChain
	for i := 0; i < len(subdomains); i++ {
		// skip last item since it is an empty string
		if i > 0 {
			currentDomain = subdomains[len(subdomains)-1-i] + "." + currentDomain
		}
		leafHashes, ok := policyDnsNameCache[currentDomain]
		if ok {
			for _, leafHash := range leafHashes {
				leafCacheEntry, ok := policyCache[leafHash]
				if !ok {
					return nil, fmt.Errorf("Inconsistent caches: policy with hash %s does not exist", leafHash)
				}
				chain, err := getPolicyCertificateChainWithLatestTimestamp(leafCacheEntry.immutableHash, e2ld, domainRootPolicyCertificateChain)
				if err != nil {
					return nil, fmt.Errorf("Failed to get policy cert chain with latest timestamp: %s", err)
				}
				if chain != nil {
					if finalChain == nil || chain.DomainLatestMinMaxTimestamp.After(finalChain.DomainLatestMinMaxTimestamp) {
						finalChain = chain
					}
				}
			}
		}
	}
	return finalChain, nil
}

func getNewestChain(chains []*PolicyCertificateChain) (*PolicyCertificateChain, error) {
	// TODO: handle cool-off period

	var newestChain *PolicyCertificateChain
	for i, chain := range chains {
		if i == 0 || chain.DomainRootIssuanceTimestamp.After(newestChain.DomainRootIssuanceTimestamp) {
			newestChain = chain
		}
	}
	return newestChain, nil
}

// remove trailing dots from domain names
func normalizeDomain(d string) string {
	dNormalized := d
	if strings.HasSuffix(dNormalized, ".") {
		dNormalized = dNormalized[:len(dNormalized)-1]
	}
	return dNormalized
}

// checks whether d1 is a subdomain of d2
// assumes that both inputs are valid domains without any wildcards
func isSameOrSubdomain(d1, d2 string) bool {
	d2Suffix := normalizeDomain(d2)
	if len(d2Suffix) > 0 {
		d2Suffix = "." + d2Suffix
	}
	return d1 == d2 || strings.HasSuffix(d1, d2Suffix)
}

// finds all certificates in the chain that are in the relying party's root store and returns a list
// of their X.509 subject names
func findRootStoreCertificateSubjects(chain []*x509.Certificate) (subjects []string) {
	for _, c := range chain {
		if entry, ok := certificateCache[GetRawCertificateHash(c)]; ok && entry.trustRoot {
			subjects = append(subjects, c.Subject.ToRDNSequence().String())
		}
	}
	return subjects
}

// Evaluate whether connection should be allowed according to
// policy mode based on current state of the cache.
func VerifyPolicy(trustInfo *PolicyTrustInfo) error {
	e2ld, err := publicsuffix.EffectiveTLDPlusOne(trustInfo.DNSName)
	if err != nil {
		return fmt.Errorf("Failed to get E2LD of %s: %s", trustInfo.DNSName, err)
	}

	// TODO (cyrill): ensure that enough map servers are queried and that enough full responses were returned

	// debug
	// fmt.Printf("root cert subject: %s\n", trustInfo.CertificateChain[len(trustInfo.CertificateChain)-1].Subject.ToRDNSequence().String())

	// get all certificate chains for the E2LD
	e2ldChains, err := findPolicyCertificateChainsForE2LD(e2ld)
	if err != nil {
		return err
	}
	fmt.Printf("domain root chains: %+v\n", e2ldChains)
	if len(e2ldChains) == 0 {
		// no applicable policy certificates exist
		trustInfo.EvaluationResult = 1
		return nil
	}

	// remove expired policy certificates
	nonExpiredE2ldChains := removeInvalidPolicyCertificateChains(e2ldChains, time.Now())

	// only consider certificate chains with the highest trust level
	highestTrustLevelE2ldChains := filterHighestTrustLevelPolicyCertificateChains(nonExpiredE2ldChains)

	// find newest chain for e2ld
	newestE2ldChain, err := getNewestChain(highestTrustLevelE2ldChains)
	if err != nil {
		return err
	}

	// find newest chain containing e2ld
	applicableChain, err := findPolicyCertificateChainForDomain(trustInfo.DNSName, newestE2ldChain)
	if err != nil {
		return err
	}
	fmt.Printf("applicable chain: %+v\n", applicableChain)
	trustInfo.PolicyChain = append(trustInfo.PolicyChain, applicableChain.PolicyCertificates...)
	trustInfo.PolicyChainTrustLevel = applicableChain.TrustLevel

	// extract policies and validate certificate based on extracted policies
	rootStoreCertificateSubjects := findRootStoreCertificateSubjects(trustInfo.CertificateChain)
	for idx, policyCert := range applicableChain.PolicyCertificates {
		err := policyCert.PolicyAttributes.ValidateAttributes()
		if err != nil {
			return fmt.Errorf("Failed to validate attributes for domain %s: %s", policyCert.Domain(), err)
		}

		// check for the status of the subdomains
		policyCertDomain := normalizeDomain(policyCert.Domain())
		domainValidity := policyCert.PolicyAttributes.CheckDomainValidity(policyCertDomain, trustInfo.DNSName)

		// check if the domain should not consider policies
		if idx == 0 && domainValidity == common.PolicyAttributeDomainExcluded {
			trustInfo.DomainExcluded = true
		}

		// check if the domain is allowed or not
		if domainValidity == common.PolicyAttributeDomainAllowed {
			// no conflicting domain attribute
		} else if domainValidity == common.PolicyAttributeDomainDisallowed {
			attr := &common.PolicyAttributes{AllowedSubdomains: policyCert.PolicyAttributes.AllowedSubdomains, DisallowedSubdomains: policyCert.PolicyAttributes.DisallowedSubdomains}
			confAttr := &ConflictingPolicyAttribute{Domain: policyCert.Domain(), Attribute: attr}
			trustInfo.ConflictingPolicyAttributes = append(trustInfo.ConflictingPolicyAttributes, confAttr)
		}

		// check for allowed CAs
		if len(policyCert.PolicyAttributes.AllowedCAs) > 0 {
			var chainContainsAllowedCa bool
			for _, subject := range rootStoreCertificateSubjects {
				if slices.Contains(policyCert.PolicyAttributes.AllowedCAs, subject) {
					chainContainsAllowedCa = true
				}
			}
			if !chainContainsAllowedCa {
				attr := &common.PolicyAttributes{AllowedCAs: policyCert.PolicyAttributes.AllowedCAs}
				confAttr := &ConflictingPolicyAttribute{Domain: policyCert.Domain(), Attribute: attr}
				trustInfo.ConflictingPolicyAttributes = append(trustInfo.ConflictingPolicyAttributes, confAttr)
			}
		}
	}
	if len(trustInfo.ConflictingPolicyAttributes) > 0 && !trustInfo.DomainExcluded {
		trustInfo.EvaluationResult = 0
	} else {
		trustInfo.EvaluationResult = 1
	}

	return nil
}
