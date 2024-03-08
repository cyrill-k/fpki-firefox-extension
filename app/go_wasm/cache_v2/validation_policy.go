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
	}
	return policyTrustInfo
}

type PolicyTrustPreference struct {
	// PCA public keys
	PCAPublicKey string

	// TODO (cyrill): also implement setting the trust preferences for specific policy certificate
	// // Immutable hash of PCA certificate
	// PCAImmutableHash string

	// map CA set to TrustLevel
	TrustLevel int
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
}

// maps a domain name to a set of legacy trust preferences
// to be used to compute certificate chain trust levels
var policyTrustPreferences = map[string][]*PolicyTrustPreference{}

type PolicyCertificateChain struct {
	PolicyCertificates                       []*common.PolicyCertificate
	DomainRootIssuanceTimestamp              time.Time
	DomainRootMinMaxTimestamp                time.Time
	RootAndIntermediateLatestMinMaxTimestamp time.Time
	DomainLatestMinMaxTimestamp              time.Time
	TrustLevel                               int

	// DisseminationTime  time.Time
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
		domainTrustPreferences := []*PolicyTrustPreference{}
		objects := entry.([]interface{})
		for _, object := range objects {
			objectMap := object.(map[string]interface{})
			trustLevel := int(trustLevelMap[objectMap["level"].(string)].(float64))
			pcaSetID := objectMap["policy-ca-set"].(string)
			for _, pca := range pcaSetsMap[pcaSetID] {
				policyTrustPreference := &PolicyTrustPreference{
					PCAPublicKey: pcasPublicKeyMap[pca],
					TrustLevel:   trustLevel,
				}
				domainTrustPreferences = append(domainTrustPreferences, policyTrustPreference)
			}
		}
		policyTrustPreferences[domain] = domainTrustPreferences
	}
}

// find the policy certificate chain which has the latest max timestamp in the set [issuance, SPCT time 1, SPCT time 2, ...].
// The second parameter is an optional root chain (e.g., domain root cert to root cert) that must be used. If nil is passed as an argument, any chain is accepted. If no acceptable chain can be generated, nil is returned.
func getPolicyCertificateChainWithLatestTimestamp(immutableHash string, rootChain *PolicyCertificateChain) (*PolicyCertificateChain, error) {

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
	parentChain, err := getPolicyCertificateChainWithLatestTimestamp(issuerEntry.immutableIssuerHash, rootChain)
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

	// check if current cert is domain root certificate
	isDomainRootCertificate := minMaxTimestampPcEntry.Domain() != "" && (len(parentChain.PolicyCertificates) == 0 || parentChain.PolicyCertificates[0].Domain() == "")
	isDomainRootCertificateParent := minMaxTimestampPcEntry.Domain() == ""

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


	return &PolicyCertificateChain{
		PolicyCertificates:                       append([]*common.PolicyCertificate{minMaxTimestampPcEntry}, parentChain.PolicyCertificates...),
		DomainRootIssuanceTimestamp:              domainRootIssuanceTimestamp,
		DomainRootMinMaxTimestamp:                domainRootMinMaxTimestamp,
		RootAndIntermediateLatestMinMaxTimestamp: rootAndIntermediateLatestMinMaxTimestamp,
		DomainLatestMinMaxTimestamp:              domainLatestMinMaxTimestamp,
		// todo: find trust level
		TrustLevel: max(parentChain.TrustLevel, 0),
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
		chain, err := getPolicyCertificateChainWithLatestTimestamp(leafCacheEntry.immutableHash, nil)
		if err != nil {
			return chains, fmt.Errorf("Failed to get policy cert chain with latest timestamp: %s", err)
		}
		chains = append(chains, chain)
	}
	return chains, nil
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
				chain, err := getPolicyCertificateChainWithLatestTimestamp(leafCacheEntry.immutableHash, domainRootPolicyCertificateChain)
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

	// find newest chain for e2ld
	newestE2ldChain, err := getNewestChain(e2ldChains)
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

	// extract policies and validate certificate based on extracted policies
	rootCertificate := trustInfo.CertificateChain[len(trustInfo.CertificateChain)-1].Subject.ToRDNSequence().String()
	for _, policyCert := range applicableChain.PolicyCertificates {

		// check for allowed CAs
		if len(policyCert.PolicyAttributes.TrustedCA) > 0 {
			if !slices.Contains(policyCert.PolicyAttributes.TrustedCA, rootCertificate) {
				attr := &common.PolicyAttributes{TrustedCA: policyCert.PolicyAttributes.TrustedCA}
				confAttr := &ConflictingPolicyAttribute{Domain: policyCert.Domain(), Attribute: attr}
				trustInfo.ConflictingPolicyAttributes = append(trustInfo.ConflictingPolicyAttributes, confAttr)
			}
		}

		// check for allowed subdomains
		policyCertDomain := normalizeDomain(policyCert.Domain())
		// don't perform subdomain checks if the requested domain is identical to the policy's domain
		if trustInfo.DNSName != policyCertDomain {
			coversDomain := func(subdomain string) bool {
				var allowedSubdomain string
				if subdomain != "" && policyCertDomain != "" {
					allowedSubdomain = subdomain + "." + policyCertDomain
				} else {
					allowedSubdomain = subdomain + policyCertDomain
				}
				return isSameOrSubdomain(trustInfo.DNSName, allowedSubdomain)
			}
			if len(policyCert.PolicyAttributes.AllowedSubdomains) > 0 {
				if !slices.ContainsFunc(policyCert.PolicyAttributes.AllowedSubdomains, coversDomain) {
					attr := &common.PolicyAttributes{AllowedSubdomains: policyCert.PolicyAttributes.AllowedSubdomains}
					confAttr := &ConflictingPolicyAttribute{Domain: policyCert.Domain(), Attribute: attr}
					trustInfo.ConflictingPolicyAttributes = append(trustInfo.ConflictingPolicyAttributes, confAttr)
				}
			}
		}
	}
	if len(trustInfo.ConflictingPolicyAttributes) > 0 {
		trustInfo.EvaluationResult = 0
	} else {
		trustInfo.EvaluationResult = 1
	}

	return nil
}
