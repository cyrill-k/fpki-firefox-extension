package cache_v2

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"slices"
	"testing"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/stretchr/testify/require"
)

var pcaPublicKeyMap = map[string]int{
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6IsLjlUm9jxztdaBL8UGaF9ODHQR5lILSrX+gyYBHV++Pc1wbly0furftUbbPYNioXw8i/2a4zXnSejKHih0Oqbwg2TEwEmKwafdXmNLrxUgox2ML3omvIott6SU8rK0O2mHPBW1kkdOiaE4EHEQh7iu+9jNJBBSuQFjKgDnMWGXeUDRjIn0w//5nGY46ry5zUaE5guvBy/oB2lbrv6RH4eT9AJ9LAK/0dT3G9JD9Bk4s+PePd8OujIPp/7ioL70W1YngRVz6uU/MEdI9IdhLqZHmso9w5Ic6XoRo2X0qDPRHNb63HrQkxEWN3/Qpqd/WBq3tMJn/VMsL8CByFl+tQIDAQAB": 3,
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqDtfrU4umz3EYw8Vj7RvID59jsyAXz8TrCCSDnFfpHdJ6XKLtddG9WvKm2FhAbvNRx3g4adblUWdXkMeAuxl3FSkhU4IhMCexXTMUD3T+1wxGCUYPnDcpr3Wcc+xWY9k0dv2btCoAENhSXz4NLlGC7USynN0/eoWMFDMlI8yndfTxS/xVUs5pCzVxcWUNV0KPlo/JgaeZszKCgHAU0z+iYQcfhbkJru7sYGHtIxSLQj6coeOpGmev1fzaGByzNb8wcPEvPrU5IO5dVyiLYJYo4f2JODKSumNrOktYjd5WTxxZsqUG+3/qVwQLC9dr+gWvPRw/WA28MClt1fl/ayIaQIDAQAB": 2,
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxUcoNh2D7lUwVftPIb3P45NMepkXSQRC1JLznWhKRwjWRmYH9CLwhYoPuE8WgLWpq1kBSoTlTQtR8aSXQ9WsaABgs4OZvHp/+TO4cAmua/KzxiPsdAqKfF21NNKOer4tPIF9KynU+e+PUsjdB1Pvq8EjEXsmSVrZ4NgolT3gXyqbxanHZjDLlUrRA0X0YMvf4ywGdiTPCkS1aUekGeolY1xUwHGhL/USDcqguKaRXVmYR7mtw1P8LaZCPjwXQ7XSHSAJ49N7eSthKPfJHJpx3bLfNlWvVQCuJU4J2QnCeRyBdrtflWAkYZX2MoUpCTLp/0NSj42WK2XdRMVOMkt1NQIDAQAB": 1,
}

// check that reading a trust preference from a config succeeds
func TestInitializePolicyTrustPreferences(t *testing.T) {
	configMap, err := ReadJsonFileAsMap("embedded/unit_test/validation/policy_validation_config.json")
	require.NoError(t, err, "Read JSON config file")
	InitializePolicyTrustPreferences(configMap)
	for publicKey, trustLevel := range policyTrustPreferences["*"].PublicKeyTrustLevelMap {
		require.Equal(t, pcaPublicKeyMap[publicKey], trustLevel)
	}
}

func testPolicyValidationInitializeCaches(t *testing.T) {
	// policy certificate cache
	testInitializePolicyCache(t)

	// X.509 certificate cache
	resetCache(t)
	trustStoreDir := "embedded/unit_test/cache/root_certificates"
	files, err := os.ReadDir(trustStoreDir)
	require.NoError(t, err)
	nCertificates := InitializeCache(trustStoreDir)
	if len(files) != nCertificates {
		log.Fatalf("wanted: %d, got %d", len(files), nCertificates)
	}
}

func testCreatePolicy(t *testing.T, domain string) {
	cert, _ := testCreatePolicyCertificate(t, domain, "none", 0, nil, nil, common.PolicyAttributes{})
	AddPoliciesToCache([]*common.PolicyCertificate{cert})
}

func testCreateCertificateChain(t *testing.T, domain string) ([]*x509.Certificate, []*rsa.PrivateKey) {
	var certificateChain []*x509.Certificate
	var privateKeys []*rsa.PrivateKey

	// read root certificate
	pemBytes, err := cacheFileSystem.ReadFile("embedded/unit_test/cache/root_certificates/root_certificate.pem")
	require.NoError(t, err)
	pemBlock, _ := pem.Decode(pemBytes)
	certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	require.NoError(t, err)

	pemBytes, err = cacheFileSystem.ReadFile("embedded/unit_test/cache/root_privatekeys/root_privatekey.pem")
	require.NoError(t, err)
	pemBlock, _ = pem.Decode(pemBytes)
	privateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	require.NoError(t, err)
	certificateChain = append(certificateChain, certificate)
	privateKeys = append(privateKeys, privateKey)

	// create intermediate CA
	parent := certificate
	parentSigner := privateKey

	template, err := CreateCertificateTemplate(big.NewInt(int64(1)), []string{"intmCA1"}, 1, 1, 1, 1, true, parent, x509.SHA256WithRSA)
	require.NoError(t, err)
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(1))))
	require.NoError(t, err)
	pemBytes, err = CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(0))))
	require.NoError(t, err)

	pemBlock, _ = pem.Decode(pemBytes)
	certificate, err = x509.ParseCertificate(pemBlock.Bytes)
	require.NoError(t, err)

	certificateChain = append(certificateChain, certificate)
	privateKeys = append(privateKeys, privateKey)

	// create leaf certificate
	parent = certificate
	parentSigner = privateKey
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(2))))
	require.NoError(t, err)
	template, err = CreateCertificateTemplate(big.NewInt(int64(2)), []string{"leaf1"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
	require.NoError(t, err)

	pemBytes, err = CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(0))))
	require.NoError(t, err)

	pemBlock, _ = pem.Decode(pemBytes)
	certificate, err = x509.ParseCertificate(pemBlock.Bytes)
	require.NoError(t, err)
	certificateChain = append(certificateChain, certificate)
	privateKeys = append(privateKeys, privateKey)

	// reverse chain to start with the leaf certificate, and end with the root certificate
	slices.Reverse(certificateChain)
	slices.Reverse(privateKeys)
	return certificateChain, privateKeys
}

func testAddCertificateToCache(t *testing.T, certificate *x509.Certificate, isInTrustRoot bool) {
	hash := GetRawCertificateHash(certificate)
	issuerAKIHash := GetRawCertificateIssuerAKIHash(certificate)
	subjectSKIHash := GetRawCertificateSubjectSKIHash(certificate)
	certificateCacheEntry := &CertificateCacheEntry{
		certificate:   certificate,
		issuerAKIHash: issuerAKIHash,
		trustRoot:     isInTrustRoot,
	}
	certificateCache[hash] = certificateCacheEntry

	subjectSKICacheEntry, cached := subjectSKICache[subjectSKIHash]
	if !cached {
		subjectSKICacheEntry = newSubjectSKICacheEntry()
		subjectSKICache[subjectSKIHash] = subjectSKICacheEntry
	}
	subjectSKICacheEntry.certificates[hash] = struct{}{}
}

func TestPolicyVerifySuccessNoAttributes(t *testing.T) {
	// initialization
	testPolicyValidationInitializeCaches(t)
	TestInitializePolicyTrustPreferences(t)

	// generate policy certificate
	cert, _ := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{})
	AddPoliciesToCache([]*common.PolicyCertificate{cert})

	// generate X.509 certificate
	chain, _ := testCreateCertificateChain(t, "www.example.com")

	// certificate verification (succeeds if no attributes are specified, i.e., default is to allow
	// any certificate)
	ti := NewPolicyTrustInfo("www.example.com", chain)
	err := VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, SUCCESS, ti.EvaluationResult)
	require.Equal(t, 3, ti.PolicyChainTrustLevel)
}

func TestPolicyVerifyFailureAllowedSubdomainsWildcard(t *testing.T) {
	// initialization
	testPolicyValidationInitializeCaches(t)
	TestInitializePolicyTrustPreferences(t)

	// generate policy certificate
	cert, _ := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{AllowedSubdomains: []string{"sub"}, DisallowedSubdomains: []string{"*"}})
	AddPoliciesToCache([]*common.PolicyCertificate{cert})

	// generate X.509 certificate
	chain, _ := testCreateCertificateChain(t, "www.example.com")

	// certificate verification (verification fails for certificates matching the disallowed
	// subdomains wildcard)
	ti := NewPolicyTrustInfo("www.example.com", chain)
	err := VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, FAILURE, ti.EvaluationResult)
	require.Equal(t, 3, ti.PolicyChainTrustLevel)
}

func TestPolicyVerifySuccessAllowedSubdomains(t *testing.T) {
	// initialization
	testPolicyValidationInitializeCaches(t)
	TestInitializePolicyTrustPreferences(t)

	// generate policy certificate
	cert, _ := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{AllowedSubdomains: []string{"www"}, DisallowedSubdomains: []string{"*"}})
	AddPoliciesToCache([]*common.PolicyCertificate{cert})

	// generate X.509 certificate
	chain, _ := testCreateCertificateChain(t, "www.example.com")

	// certificate verification (verification succeeds for certificates of allowed subdomains)
	ti := NewPolicyTrustInfo("www.example.com", chain)
	err := VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, SUCCESS, ti.EvaluationResult)
	require.Equal(t, 3, ti.PolicyChainTrustLevel)
}

func TestPolicyVerifyFailureDisallowedSubdomain(t *testing.T) {
	// initialization
	testPolicyValidationInitializeCaches(t)
	TestInitializePolicyTrustPreferences(t)

	// generate policy certificate
	cert, _ := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{DisallowedSubdomains: []string{"www"}})
	AddPoliciesToCache([]*common.PolicyCertificate{cert})

	// generate X.509 certificate
	chain, _ := testCreateCertificateChain(t, "www.example.com")

	// certificate verification (verification fails for certificates of disallowed subdomains)
	ti := NewPolicyTrustInfo("www.example.com", chain)
	err := VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, FAILURE, ti.EvaluationResult)
	require.Equal(t, 3, ti.PolicyChainTrustLevel)
}

func TestPolicyVerifySuccessAllowedCa(t *testing.T) {
	// initialization
	testPolicyValidationInitializeCaches(t)
	TestInitializePolicyTrustPreferences(t)

	// generate policy certificate
	cert, _ := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{AllowedCAs: []string{"SERIALNUMBER=1,CN=intmCA1"}})
	AddPoliciesToCache([]*common.PolicyCertificate{cert})

	// generate X.509 certificate
	chain, _ := testCreateCertificateChain(t, "www.example.com")
	// add intermediate cert "SERIALNUMBER=1,CN=intmCA1" to root store
	testAddCertificateToCache(t, chain[1], true)
	// add leaf cert as a regular X.509 cert
	testAddCertificateToCache(t, chain[0], false)

	// certificate verification (if the CA is listed as allowed CA, verification succeeds)
	ti := NewPolicyTrustInfo("www.example.com", chain)
	err := VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, SUCCESS, ti.EvaluationResult)
	require.Equal(t, 3, ti.PolicyChainTrustLevel)
}

func TestPolicyVerifyFailureDisallowedCa(t *testing.T) {
	// initialization
	testPolicyValidationInitializeCaches(t)
	TestInitializePolicyTrustPreferences(t)

	// generate policy certificate
	cert, _ := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{AllowedCAs: []string{"nonExistingCA"}})
	AddPoliciesToCache([]*common.PolicyCertificate{cert})

	// generate X.509 certificate
	chain, _ := testCreateCertificateChain(t, "www.example.com")
	// add intermediate cert "SERIALNUMBER=1,CN=intmCA1" to root store
	testAddCertificateToCache(t, chain[1], true)
	// add leaf cert as a regular X.509 cert
	testAddCertificateToCache(t, chain[0], false)

	// certificate verification (if intermediate CA is not listed as allowed CA, verification fails)
	ti := NewPolicyTrustInfo("www.example.com", chain)
	err := VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, FAILURE, ti.EvaluationResult)
	require.Equal(t, 3, ti.PolicyChainTrustLevel)
}

func TestPolicyVerifySuccessIgnorePolicyWithLowerTrustLevel(t *testing.T) {
	// initialization
	testPolicyValidationInitializeCaches(t)
	TestInitializePolicyTrustPreferences(t)

	// generate policy certificate
	// policy that allows issuance with trust level 3
	cert, _ := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{AllowedCAs: []string{"SERIALNUMBER=1,CN=intmCA1"}})
	AddPoliciesToCache([]*common.PolicyCertificate{cert})
	// policy that disallows issuance with trust level 2
	cert, _ = testCreatePolicyCertificate(t, "example.com", "none", 1, nil, nil, common.PolicyAttributes{AllowedCAs: []string{"nonExistingCA"}})
	AddPoliciesToCache([]*common.PolicyCertificate{cert})

	// generate X.509 certificate
	chain, _ := testCreateCertificateChain(t, "www.example.com")
	// add intermediate cert "SERIALNUMBER=1,CN=intmCA1" to root store
	testAddCertificateToCache(t, chain[1], true)
	// add leaf cert as a regular X.509 cert
	testAddCertificateToCache(t, chain[0], false)

	// certificate verification (prohibiting policy has lower trust level and is ignored)
	ti := NewPolicyTrustInfo("www.example.com", chain)
	err := VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, SUCCESS, ti.EvaluationResult)
	require.Equal(t, 3, ti.PolicyChainTrustLevel)
}

func TestPolicyVerifyFailurePreferLatestDomainRootPolicy(t *testing.T) {
	// initialization
	testPolicyValidationInitializeCaches(t)
	TestInitializePolicyTrustPreferences(t)

	// generate policy certificate
	// policy that allows issuance with trust level 3
	cert, _ := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{AllowedCAs: []string{"SERIALNUMBER=1,CN=intmCA1"}})
	AddPoliciesToCache([]*common.PolicyCertificate{cert})
	// policy that disallows issuance with trust level 3
	cert, _ = testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{AllowedCAs: []string{"nonExistingCA"}})
	AddPoliciesToCache([]*common.PolicyCertificate{cert})

	// generate X.509 certificate
	chain, _ := testCreateCertificateChain(t, "www.example.com")
	// add intermediate cert "SERIALNUMBER=1,CN=intmCA1" to root store
	testAddCertificateToCache(t, chain[1], true)
	// add leaf cert as a regular X.509 cert
	testAddCertificateToCache(t, chain[0], false)

	// certificate verification (policy verification uses most recent domain root policy certificate
	// for "example.com" which prohibits the CA)
	ti := NewPolicyTrustInfo("www.example.com", chain)
	err := VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, FAILURE, ti.EvaluationResult)
	require.Equal(t, 3, ti.PolicyChainTrustLevel)
}

func TestPolicyVerifyFailurePreferLatestDomainPolicy(t *testing.T) {
	// initialization
	testPolicyValidationInitializeCaches(t)
	TestInitializePolicyTrustPreferences(t)

	// generate policy certificate
	// domain root policy that allows issuance with trust level 3
	domainRootPolicy, domainRootPrivateKey := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{})
	AddPoliciesToCache([]*common.PolicyCertificate{domainRootPolicy})
	// domain policy that disallows issuance with trust level 3 (will be discarded in favor of the
	// newer domain policy below)
	cert, _ := testCreatePolicyCertificate(t, "sub.example.com", "none", 0, domainRootPolicy, domainRootPrivateKey, common.PolicyAttributes{AllowedCAs: []string{"nonExistingCA"}})
	AddPoliciesToCache([]*common.PolicyCertificate{cert})
	// newer domain policy that allows issuance with trust level 3
	cert, _ = testCreatePolicyCertificate(t, "sub.example.com", "none", 0, domainRootPolicy, domainRootPrivateKey, common.PolicyAttributes{AllowedCAs: []string{"SERIALNUMBER=1,CN=intmCA1"}})
	AddPoliciesToCache([]*common.PolicyCertificate{cert})

	// generate X.509 certificate
	chain, _ := testCreateCertificateChain(t, "www.example.com")
	// add intermediate cert "SERIALNUMBER=1,CN=intmCA1" to root store
	testAddCertificateToCache(t, chain[1], true)
	// add leaf cert as a regular X.509 cert
	testAddCertificateToCache(t, chain[0], false)

	// certificate verification (policy verification uses most recent policy certificate for
	// "sub.example.com" which does not prohibit the CA)
	ti := NewPolicyTrustInfo("sub.example.com", chain)
	err := VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, SUCCESS, ti.EvaluationResult)
	require.Equal(t, 3, ti.PolicyChainTrustLevel)
}

func TestPolicyVerifySuccessExcludedSubdomains(t *testing.T) {
	// initialization
	testPolicyValidationInitializeCaches(t)
	TestInitializePolicyTrustPreferences(t)

	// generate policy certificate
	// domain root policy that disallows issuance with trust level 3 but excludes "excluded.example.com"
	domainRootPolicy, _ := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{ExcludedSubdomains: []string{"excluded"}, AllowedCAs: []string{"nonExistingCA"}})
	AddPoliciesToCache([]*common.PolicyCertificate{domainRootPolicy})

	// generate X.509 certificate
	chain, _ := testCreateCertificateChain(t, "www.example.com")
	// add intermediate cert "SERIALNUMBER=1,CN=intmCA1" to root store
	testAddCertificateToCache(t, chain[1], true)
	// add leaf cert as a regular X.509 cert
	testAddCertificateToCache(t, chain[0], false)

	// certificate verification (policies apply to excluded subdomains)
	ti := NewPolicyTrustInfo("sub.example.com", chain)
	err := VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, FAILURE, ti.EvaluationResult)
	require.Equal(t, 3, ti.PolicyChainTrustLevel)

	// generate X.509 certificate
	chain, _ = testCreateCertificateChain(t, "excluded.example.com")
	// add intermediate cert "SERIALNUMBER=1,CN=intmCA1" to root store
	testAddCertificateToCache(t, chain[1], true)
	// add leaf cert as a regular X.509 cert
	testAddCertificateToCache(t, chain[0], false)

	// certificate verification (policies do not apply to excluded subdomains)
	ti = NewPolicyTrustInfo("excluded.example.com", chain)
	err = VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, SUCCESS, ti.EvaluationResult)
	require.Equal(t, 3, ti.PolicyChainTrustLevel)

	// generate X.509 certificate
	chain, _ = testCreateCertificateChain(t, "www.excluded.example.com")
	// add intermediate cert "SERIALNUMBER=1,CN=intmCA1" to root store
	testAddCertificateToCache(t, chain[1], true)
	// add leaf cert as a regular X.509 cert
	testAddCertificateToCache(t, chain[0], false)

	// certificate verification (also exclude subdomains)
	ti = NewPolicyTrustInfo("www.excluded.example.com", chain)
	err = VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, SUCCESS, ti.EvaluationResult)
	require.Equal(t, 3, ti.PolicyChainTrustLevel)
}

func TestPolicyVerifySuccessIgnorePolicyForDifferentRootDomains(t *testing.T) {
	// initialization
	testPolicyValidationInitializeCaches(t)
	TestInitializePolicyTrustPreferences(t)

	// generate policy certificate
	// domain root policy that disallows issuance with trust level 3 for "otherdomain.com"
	domainRootPolicy, _ := testCreatePolicyCertificate(t, "otherdomain.com", "none", 0, nil, nil, common.PolicyAttributes{AllowedCAs: []string{"nonExistingCA"}})
	AddPoliciesToCache([]*common.PolicyCertificate{domainRootPolicy})
	// domain root policy that allows issuance with trust level 2 for "example.com"
	domainRootPolicy, _ = testCreatePolicyCertificate(t, "example.com", "none", 1, nil, nil, common.PolicyAttributes{})
	AddPoliciesToCache([]*common.PolicyCertificate{domainRootPolicy})

	// generate X.509 certificate
	chain, _ := testCreateCertificateChain(t, "www.example.com")
	// add intermediate cert "SERIALNUMBER=1,CN=intmCA1" to root store
	testAddCertificateToCache(t, chain[1], true)
	// add leaf cert as a regular X.509 cert
	testAddCertificateToCache(t, chain[0], false)

	// certificate verification
	ti := NewPolicyTrustInfo("www.example.com", chain)
	err := VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, SUCCESS, ti.EvaluationResult)
	require.Equal(t, 2, ti.PolicyChainTrustLevel)

	// certificate verification (fails since "otherdomain.com" requires a non-existent CA)
	ti = NewPolicyTrustInfo("otherdomain.com", chain)
	err = VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, FAILURE, ti.EvaluationResult)
	require.Equal(t, 3, ti.PolicyChainTrustLevel)

	// certificate verification (succeeds since there is no policy for "nopolicydomain.com" but the
	// browser's legacy validation will fail since the leaf certificate is issued for the wrong
	// domain)
	ti = NewPolicyTrustInfo("nopolicydomain.com", chain)
	err = VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, SUCCESS, ti.EvaluationResult)
	require.Equal(t, (*PolicyCertificateChain)(nil), ti.PolicyChain)
}

func TestPolicyVerifyMultiplePoliciesForRootDomain(t *testing.T) {
	// initialization
	testPolicyValidationInitializeCaches(t)
	TestInitializePolicyTrustPreferences(t)

	// generate policy certificate
	// domain root policy that allows issuance (A)
	domainRootPolicy, domainRootPrivateKey := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{})
	AddPoliciesToCache([]*common.PolicyCertificate{domainRootPolicy})
	// domain root child policy B that disallows issuance (A->B)
	domainRootChildPolicy, _ := testCreatePolicyCertificate(t, "example.com", "none", 1, domainRootPolicy, domainRootPrivateKey, common.PolicyAttributes{AllowedCAs: []string{"nonExistingCA"}})
	AddPoliciesToCache([]*common.PolicyCertificate{domainRootChildPolicy})
	// leaf policy (C) that allows issuance (A->C)
	cert, _ := testCreatePolicyCertificate(t, "www.example.com", "none", 0, domainRootPolicy, domainRootPrivateKey, common.PolicyAttributes{})
	AddPoliciesToCache([]*common.PolicyCertificate{cert})

	// generate X.509 certificate
	chain, _ := testCreateCertificateChain(t, "www.example.com")
	// add intermediate cert "SERIALNUMBER=1,CN=intmCA1" to root store
	testAddCertificateToCache(t, chain[1], true)
	// add leaf cert as a regular X.509 cert
	testAddCertificateToCache(t, chain[0], false)

	// certificate verification (since the leaf policy (C) is the latest policy certificate for
	// www.example.com, chain A->C is preferred over B->C and thus the domainRootChildPolicy (B) is not
	// part of the considered chain)
	ti := NewPolicyTrustInfo("www.example.com", chain)
	err := VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, SUCCESS, ti.EvaluationResult)
	require.Equal(t, 3, ti.PolicyChainTrustLevel)
}

func TestPolicyVerifySuccessRootPolicyCertificateWithNonEmptyDomain(t *testing.T) {
	// initialization
	testPolicyValidationInitializeCaches(t)
	TestInitializePolicyTrustPreferences(t)

	// generate policy certificate
	// root policy that allows issuance (A)
	rootPolicy, rootPrivateKey := testCreatePolicyCertificate(t, "com", "none", 0, nil, nil, common.PolicyAttributes{})
	AddPoliciesToCache([]*common.PolicyCertificate{rootPolicy})
	// domain root policy B that allows issuance (A->B)
	domainRootPolicy, _ := testCreatePolicyCertificate(t, "example.com", "none", 1, rootPolicy, rootPrivateKey, common.PolicyAttributes{})
	AddPoliciesToCache([]*common.PolicyCertificate{domainRootPolicy})
	// leaf policy (C) that disallows issuance (A->C)
	cert, _ := testCreatePolicyCertificate(t, "www.example.com", "none", 0, rootPolicy, rootPrivateKey, common.PolicyAttributes{AllowedCAs: []string{"nonExistingCA"}})
	AddPoliciesToCache([]*common.PolicyCertificate{cert})

	// generate X.509 certificate
	chain, _ := testCreateCertificateChain(t, "www.example.com")
	// add intermediate cert "SERIALNUMBER=1,CN=intmCA1" to root store
	testAddCertificateToCache(t, chain[1], true)
	// add leaf cert as a regular X.509 cert
	testAddCertificateToCache(t, chain[0], false)

	// certificate verification (even though the leaf policy (C), which is the latest policy
	// certificate for a subdomain of example.com is the latest policy and forbids issuance, only
	// policies that are children of the domain root policy (B) are considered for verification)
	ti := NewPolicyTrustInfo("www.example.com", chain)
	err := VerifyPolicy(ti)
	require.NoError(t, err)
	fmt.Printf("PolicyTrustInfo=%+v\n", ti)
	require.Equal(t, SUCCESS, ti.EvaluationResult)
	require.Equal(t, 3, ti.PolicyChainTrustLevel)
}
