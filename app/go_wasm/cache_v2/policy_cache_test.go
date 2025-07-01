package cache_v2

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/common/crypto"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

const PCA_STORE_DIR = "embedded/unit_test/policy_cache/root_certificates"

func resetPolicyCache(t *testing.T) {
	policyCache = map[string]*PolicyCacheEntry{}
	immutablePolicyCache = map[string]*ImmutablePolicyCacheEntry{}
	ignoredPolicyHashes = map[string]struct{}{}
	policyDnsNameCache = map[string][]string{}
}

// Create a policy certificate for a given domain that:
// is valid (defect == "none")
// is expired (defect == "expired")
// cannot issue child policy certificate (defect == "cannot-issue")
// is valid before the parent is valid (defect == "validity-too-early")
// is still valid after the parent is not valid anymore (defect == "validity-too-late")
// has an invalid signature (defect == "invalid-sig")
func testCreatePolicyCertificate(t *testing.T, domain string, defect string, pcaId int, parentCert *common.PolicyCertificate, parentPrivateKey *rsa.PrivateKey, policyAttributes common.PolicyAttributes) (*common.PolicyCertificate, *rsa.PrivateKey) {
	if parentCert == nil {
		// load PCA certificate and private key if no parent cert is given
		var err error
		parentCert, err = common.JsonFileToPolicyCert(fmt.Sprintf("embedded/unit_test/policy_cache/root_certificates/root_certificate_%d.pc", pcaId))
		require.NoError(t, err)
		privateKeyBytes, err := os.ReadFile(fmt.Sprintf("embedded/unit_test/policy_cache/root_privatekeys/root_privatekey_%d.pem", pcaId))
		require.NoError(t, err)
		p, _ := pem.Decode(privateKeyBytes)
		parentPrivateKey, err = x509.ParsePKCS1PrivateKey(p.Bytes)
		require.NoError(t, err)
	}

	// create RSA private key
	privateKey, err := CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(0))))
	require.NoError(t, err)

	// create certificate signing request
	notBefore := maxTime(time.Now().AddDate(-1, 0, 0), parentCert.NotBefore)
	notAfter := minTime(time.Now().AddDate(1, 0, 0), parentCert.NotAfter)

	if defect == "validity-too-early" {
		notBefore = parentCert.NotBefore.AddDate(0, 0, -1)
	}

	if defect == "validity-too-late" {
		notAfter = parentCert.NotAfter.AddDate(0, 0, 1)
	}

	// generate an expired policy certificate
	if defect == "expired" {
		notAfter = time.Now().AddDate(0, 0, -1)
	}

	// convert the public key to byte form
	publicKeyBytes, err := util.RSAPublicToDERBytes(&privateKey.PublicKey)
	require.NoError(t, err)

	canIssue := defect != "cannot-issue"
	request := common.NewPolicyCertificateSigningRequest(0, 0, domain, notBefore, notAfter, canIssue, true, publicKeyBytes, common.RSA, common.SHA256, time.Now(), policyAttributes, nil, nil)

	// sign certificate
	cert, err := crypto.SignRequestAsIssuer(parentCert, parentPrivateKey, request)
	require.NoError(t, err)

	// modify first byte of signature value
	if defect == "invalid-sig" {
		cert.IssuerSignature[0] = cert.IssuerSignature[0] + 1
	}

	return cert, privateKey
}

func testInitializePolicyCache(t *testing.T) int {
	resetPolicyCache(t)
	files, err := os.ReadDir(PCA_STORE_DIR)
	require.NoError(t, err)
	nCertificates := InitializePolicyCache(PCA_STORE_DIR)
	require.Equal(t, len(files), nCertificates)
	require.Equal(t, len(files), len(policyCache))
	require.Equal(t, len(files), len(immutablePolicyCache))
	require.Equal(t, 0, len(ignoredPolicyHashes))
	// none of the root certificates specify a domain, hence domain == "" for all of them
	require.Equal(t, 1, len(policyDnsNameCache))
	return nCertificates
}

func TestInitializePolicyCache(t *testing.T) {
	testInitializePolicyCache(t)
}

func TestAddPolicyCertificates(t *testing.T) {
	n := testInitializePolicyCache(t)
	cert, _ := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{})
	processedPolicyHashes := AddPoliciesToCache([]*common.PolicyCertificate{cert})
	require.Equal(t, 1, len(processedPolicyHashes))
	require.Equal(t, n+1, len(policyCache))
	require.Equal(t, n+1, len(immutablePolicyCache))
	require.Equal(t, 0, len(ignoredPolicyHashes))
	require.Equal(t, 2, len(policyDnsNameCache))
}

func TestAddPolicyCertificatesWithValidDomainConstraint(t *testing.T) {
	n := testInitializePolicyCache(t)
	parentCert, parentPrivateKey := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{})
	cert, _ := testCreatePolicyCertificate(t, "sub.example.com", "none", 0, parentCert, parentPrivateKey, common.PolicyAttributes{})
	processedPolicyHashes := AddPoliciesToCache([]*common.PolicyCertificate{cert, parentCert})
	require.Equal(t, 2, len(processedPolicyHashes))
	require.Equal(t, n+2, len(policyCache))
	require.Equal(t, n+2, len(immutablePolicyCache))
	require.Equal(t, 0, len(ignoredPolicyHashes))
	require.Equal(t, 3, len(policyDnsNameCache))
}

func TestIgnoreExpiredPolicyCertificates(t *testing.T) {
	n := testInitializePolicyCache(t)
	cert, _ := testCreatePolicyCertificate(t, "example.com", "expired", 0, nil, nil, common.PolicyAttributes{})
	json, _ := common.ToJSON(cert)
	log.Println(string(json))
	processedPolicyHashes := AddPoliciesToCache([]*common.PolicyCertificate{cert})
	// expiration is checked at validation time and not when the certificate is added to the cache
	require.Equal(t, 1, len(processedPolicyHashes))
	require.Equal(t, n+1, len(policyCache))
	require.Equal(t, n+1, len(immutablePolicyCache))
	require.Equal(t, 0, len(ignoredPolicyHashes))
	require.Equal(t, 2, len(policyDnsNameCache))
}

func TestIgnoreInvalidSignaturePolicyCertificates(t *testing.T) {
	n := testInitializePolicyCache(t)
	cert, _ := testCreatePolicyCertificate(t, "example.com", "invalid-sig", 0, nil, nil, common.PolicyAttributes{})
	processedPolicyHashes := AddPoliciesToCache([]*common.PolicyCertificate{cert})
	require.Equal(t, 1, len(processedPolicyHashes))
	require.Equal(t, n+0, len(policyCache))
	require.Equal(t, n+0, len(immutablePolicyCache))
	require.Equal(t, 1, len(ignoredPolicyHashes))
	require.Equal(t, 1, len(policyDnsNameCache))
}

func TestIgnoreEarlyValidityPolicyCertificates(t *testing.T) {
	n := testInitializePolicyCache(t)
	cert, _ := testCreatePolicyCertificate(t, "example.com", "validity-too-early", 0, nil, nil, common.PolicyAttributes{})
	processedPolicyHashes := AddPoliciesToCache([]*common.PolicyCertificate{cert})
	require.Equal(t, 1, len(processedPolicyHashes))
	require.Equal(t, n+0, len(policyCache))
	require.Equal(t, n+0, len(immutablePolicyCache))
	require.Equal(t, 1, len(ignoredPolicyHashes))
	require.Equal(t, 1, len(policyDnsNameCache))
}

func TestIgnoreLateValidityPolicyCertificates(t *testing.T) {
	n := testInitializePolicyCache(t)
	cert, _ := testCreatePolicyCertificate(t, "example.com", "validity-too-late", 0, nil, nil, common.PolicyAttributes{})
	processedPolicyHashes := AddPoliciesToCache([]*common.PolicyCertificate{cert})
	require.Equal(t, 1, len(processedPolicyHashes))
	require.Equal(t, n+0, len(policyCache))
	require.Equal(t, n+0, len(immutablePolicyCache))
	require.Equal(t, 1, len(ignoredPolicyHashes))
	require.Equal(t, 1, len(policyDnsNameCache))
}

func TestIgnoreInvalidDomainConstraintPolicyCertificates(t *testing.T) {
	n := testInitializePolicyCache(t)
	parentCert, parentPrivateKey := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{})
	cert, _ := testCreatePolicyCertificate(t, "test.com", "none", 0, parentCert, parentPrivateKey, common.PolicyAttributes{})
	processedPolicyHashes := AddPoliciesToCache([]*common.PolicyCertificate{cert, parentCert})
	require.Equal(t, 2, len(processedPolicyHashes))
	require.Equal(t, n+1, len(policyCache))
	require.Equal(t, n+1, len(immutablePolicyCache))
	require.Equal(t, 1, len(ignoredPolicyHashes))
	require.Equal(t, 2, len(policyDnsNameCache))
}

func TestIgnoreIssuanceConstraintPolicyCertificates(t *testing.T) {
	n := testInitializePolicyCache(t)
	parentCert, parentPrivateKey := testCreatePolicyCertificate(t, "example.com", "cannot-issue", 0, nil, nil, common.PolicyAttributes{})
	cert, _ := testCreatePolicyCertificate(t, "example.com", "none", 0, parentCert, parentPrivateKey, common.PolicyAttributes{})
	processedPolicyHashes := AddPoliciesToCache([]*common.PolicyCertificate{cert, parentCert})
	require.Equal(t, 2, len(processedPolicyHashes))
	require.Equal(t, n+1, len(policyCache))
	require.Equal(t, n+1, len(immutablePolicyCache))
	require.Equal(t, 1, len(ignoredPolicyHashes))
	require.Equal(t, 2, len(policyDnsNameCache))
}

func TestIgnoreMultipleWildcardsPolicyCertificates(t *testing.T) {
	n := testInitializePolicyCache(t)
	cert, _ := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{AllowedSubdomains: []string{"*"}, DisallowedSubdomains: []string{"*"}})
	processedPolicyHashes := AddPoliciesToCache([]*common.PolicyCertificate{cert})
	require.Equal(t, 1, len(processedPolicyHashes))
	require.Equal(t, n+0, len(policyCache))
	require.Equal(t, n+0, len(immutablePolicyCache))
	require.Equal(t, 1, len(ignoredPolicyHashes))
	require.Equal(t, 1, len(policyDnsNameCache))
}

func TestIgnoreIdenticalSubdomainsPolicyCertificates(t *testing.T) {
	n := testInitializePolicyCache(t)
	cert, _ := testCreatePolicyCertificate(t, "example.com", "none", 0, nil, nil, common.PolicyAttributes{AllowedSubdomains: []string{"www"}, ExcludedSubdomains: []string{"www"}})
	processedPolicyHashes := AddPoliciesToCache([]*common.PolicyCertificate{cert})
	require.Equal(t, 1, len(processedPolicyHashes))
	require.Equal(t, n+0, len(policyCache))
	require.Equal(t, n+0, len(immutablePolicyCache))
	require.Equal(t, 1, len(ignoredPolicyHashes))
	require.Equal(t, 1, len(policyDnsNameCache))
}
