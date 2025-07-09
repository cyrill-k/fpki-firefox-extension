package cache_v2

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func reset(t *testing.T) {
	legacyTrustPreferences = map[string][]*LegacyTrustPreference{}
}

// check that reading a trust preference from a config succeeds
func TestInitializeLegacyTrustPreferences(t *testing.T) {
	reset(t)
	configMap, err := ReadJsonFileAsMap("embedded/unit_test/validation/config.json")
	require.NoError(t, err, "Read JSON config file")
	InitializeLegacyTrustPreferences(configMap)
	legacyTrustPreference := legacyTrustPreferences["microsoft.com"]
	require.Equal(t, 1, len(legacyTrustPreference))
	require.Equal(t, "Microsoft CA", legacyTrustPreference[0].CASetIdentifier)
	require.Equal(t, 2, len(legacyTrustPreference[0].CASubjectNames))
	require.Equal(t, 1, legacyTrustPreference[0].TrustLevel)

	legacyTrustPreference = legacyTrustPreferences["bing.com"]
	require.Equal(t, 2, len(legacyTrustPreference))
	require.Equal(t, "US CA", legacyTrustPreference[0].CASetIdentifier)
	require.Equal(t, 6, len(legacyTrustPreference[0].CASubjectNames))
	require.Equal(t, 2, legacyTrustPreference[0].TrustLevel)
	require.Equal(t, "Microsoft CA", legacyTrustPreference[1].CASetIdentifier)
	require.Equal(t, 2, len(legacyTrustPreference[1].CASubjectNames))
	require.Equal(t, 1, legacyTrustPreference[1].TrustLevel)
}

// check that the trust level is computed correctly
func TestSimpleChainTrustLevel(t *testing.T) {
	reset(t)
	configMap, err := ReadJsonFileAsMap("embedded/unit_test/validation/config_simplechain.json")
	require.NoError(t, err, "Read JSON config file")
	InitializeLegacyTrustPreferences(configMap)

	chain, _ := testSimpleChainCreate(t, nil, nil)
	chainRev := []*x509.Certificate{chain[2], chain[1], chain[0]}
	trustLevel, _, _, _ := ComputeChainTrustLevelForDomain("leaf1", chainRev)
	require.Equal(t, 1, trustLevel)

	reset(t)
	configMap, err = ReadJsonFileAsMap("embedded/unit_test/validation/config_simplechain_2.json")
	require.NoError(t, err, "Read JSON config file")
	InitializeLegacyTrustPreferences(configMap)
	trustLevel, _, _, _ = ComputeChainTrustLevelForDomain("leaf1", chainRev)
	require.Equal(t, 2, trustLevel)
}

// 2 chains
// (root -> intmCA1 -> leaf1)
// (root -> intmCA2 -> leaf1)
func testTwoChainsSameLeafDNSNameCreate(t *testing.T, chain []*x509.Certificate, keys []*rsa.PrivateKey) ([]*x509.Certificate, []*rsa.PrivateKey) {
	var certificateChain []*x509.Certificate
	var privateKeys []*rsa.PrivateKey
	if chain != nil {
		certificateChain = chain
	}
	if keys != nil {
		privateKeys = keys
	}

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

	// create first certificate chain

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

	// create second certificate chain with same leaf DNSName
	// create intermediate CA
	parent = certificateChain[0]
	parentSigner = privateKeys[0]

	template, err = CreateCertificateTemplate(big.NewInt(int64(1)), []string{"intmCA2"}, 1, 1, 1, 1, true, parent, x509.SHA256WithRSA)
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
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(3))))
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

	return certificateChain, privateKeys
}

// test that connection chain is accepted if it has the
// same trust level the cached chains
func TestVerifySame(t *testing.T) {
	reset(t)
	resetCache(t)
	trustStoreDir := "embedded/unit_test/cache/root_certificates"
	InitializeCache(trustStoreDir)
	configMap, err := ReadJsonFileAsMap("embedded/unit_test/validation/config_simplechain.json")
	require.NoError(t, err, "Read JSON config file")
	InitializeLegacyTrustPreferences(configMap)
	cc, _ := testTwoChainsSameLeafDNSNameCreate(t, nil, nil)

	ccToAddToCache := []*x509.Certificate{cc[4], cc[3]}
	ccToVerify := []*x509.Certificate{cc[2], cc[1], cc[0]}

	dnsName := "leaf1"
	AddCertificatesToCache(ccToAddToCache)
	legacyTrustInfoToVerify := NewLegacyTrustInfo(dnsName, ccToVerify)
	VerifyLegacy(legacyTrustInfoToVerify)
	require.Equal(t, SUCCESS, legacyTrustInfoToVerify.EvaluationResult)
}

// check that connection is accepted if there are no
// cached certificate chains for the domain
func TestVerifyUncached(t *testing.T) {
	reset(t)
	resetCache(t)
	cc, _ := testTwoChainsSameLeafDNSNameCreate(t, nil, nil)
	trustStoreDir := "embedded/unit_test/cache/root_certificates"
	InitializeCache(trustStoreDir)
	configMap, err := ReadJsonFileAsMap("embedded/unit_test/validation/config.json")
	require.NoError(t, err, "Read JSON config file")
	InitializeLegacyTrustPreferences(configMap)

	ccToVerify := []*x509.Certificate{cc[2], cc[1], cc[0]}

	dnsName := "leaf1"
	legacyTrustInfoToVerify := NewLegacyTrustInfo(dnsName, ccToVerify)
	trustLevel, _, _, _ := ComputeChainTrustLevelForDomain("leaf1", ccToVerify)
	require.Equal(t, 0, trustLevel)

	VerifyLegacy(legacyTrustInfoToVerify)
	require.Equal(t, SUCCESS, legacyTrustInfoToVerify.EvaluationResult)
}

// check that if connection chain has lower trust level
// than a cached chain and different leaf public keys,
// it is rejected
func TestVerifyLowerDifferent(t *testing.T) {
	reset(t)
	resetCache(t)
	cc, _ := testTwoChainsSameLeafDNSNameCreate(t, nil, nil)
	trustStoreDir := "embedded/unit_test/cache/root_certificates"
	InitializeCache(trustStoreDir)
	configMap, err := ReadJsonFileAsMap("embedded/unit_test/validation/config_lower_different.json")
	require.NoError(t, err, "Read JSON config file")
	InitializeLegacyTrustPreferences(configMap)

	ccToAddToCache := []*x509.Certificate{cc[4], cc[3]}
	ccToVerify := []*x509.Certificate{cc[2], cc[1], cc[0]}
	dnsName := "leaf1"
	AddCertificatesToCache(ccToAddToCache)
	legacyTrustInfoToVerify := NewLegacyTrustInfo(dnsName, ccToVerify)
	VerifyLegacy(legacyTrustInfoToVerify)
	require.Equal(t, FAILURE, legacyTrustInfoToVerify.EvaluationResult)
}

// 2 chains
// (root -> intmCA1 -> leaf1)
// (root -> intmCA2 -> leaf1')
// leaf1 == leaf1'
func testTwoChainsSameLeafSameSKIDNSNameCreate(t *testing.T, chain []*x509.Certificate, keys []*rsa.PrivateKey) ([]*x509.Certificate, []*rsa.PrivateKey) {
	var certificateChain []*x509.Certificate
	var privateKeys []*rsa.PrivateKey
	if chain != nil {
		certificateChain = chain
	}
	if keys != nil {
		privateKeys = keys
	}

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

	// create first certificate chain

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

	// create second certificate chain with same leaf DNSName
	// create intermediate CA
	parent = certificateChain[0]
	parentSigner = privateKeys[0]

	template, err = CreateCertificateTemplate(big.NewInt(int64(1)), []string{"intmCA2"}, 1, 1, 1, 1, true, parent, x509.SHA256WithRSA)
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
	privateKey = privateKeys[2]

	template, err = CreateCertificateTemplate(big.NewInt(int64(2)), []string{"leaf1"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
	require.NoError(t, err)

	pemBytes, err = CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(0))))
	require.NoError(t, err)

	pemBlock, _ = pem.Decode(pemBytes)
	certificate, err = x509.ParseCertificate(pemBlock.Bytes)
	require.NoError(t, err)
	certificateChain = append(certificateChain, certificate)
	privateKeys = append(privateKeys, privateKey)

	return certificateChain, privateKeys
}

// check that a connection with lower trust level than
// a cached certificate chain, but same Subject and SKI
// is accepted
func TestVerifyLowerSame(t *testing.T) {

	reset(t)
	resetCache(t)
	trustStoreDir := "embedded/unit_test/cache/root_certificates"
	InitializeCache(trustStoreDir)
	configMap, err := ReadJsonFileAsMap("embedded/unit_test/validation/config_lower_different.json")
	require.NoError(t, err, "Read JSON config file")
	InitializeLegacyTrustPreferences(configMap)

	cc, _ := testTwoChainsSameLeafSameSKIDNSNameCreate(t, nil, nil)
	ccToAddToCache := []*x509.Certificate{cc[4], cc[3]}
	ccToVerify := []*x509.Certificate{cc[2], cc[1], cc[0]}
	dnsName := "leaf1"
	AddCertificatesToCache(ccToAddToCache)
	legacyTrustInfoToVerify := NewLegacyTrustInfo(dnsName, ccToVerify)
	VerifyLegacy(legacyTrustInfoToVerify)
	require.Equal(t, SUCCESS, legacyTrustInfoToVerify.EvaluationResult)
}

// check that connection chain with higher trust level than
// all cached certificate chains are accepted.
func TestVerifyHigher(t *testing.T) {
	reset(t)
	resetCache(t)
	trustStoreDir := "embedded/unit_test/cache/root_certificates"
	cc, _ := testTwoChainsSameLeafDNSNameCreate(t, nil, nil)
	InitializeCache(trustStoreDir)
	configMap, err := ReadJsonFileAsMap("embedded/unit_test/validation/config_higher.json")
	require.NoError(t, err, "Read JSON config file")
	InitializeLegacyTrustPreferences(configMap)

	ccToAddToCache := []*x509.Certificate{cc[4], cc[3]}
	ccToVerify := []*x509.Certificate{cc[2], cc[1], cc[0]}
	dnsName := "leaf1"
	AddCertificatesToCache(ccToAddToCache)

	legacyTrustInfoToVerify := NewLegacyTrustInfo(dnsName, ccToVerify)
	VerifyLegacy(legacyTrustInfoToVerify)
	require.Equal(t, SUCCESS, legacyTrustInfoToVerify.EvaluationResult)
}
