package cache_v2

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/big"
	"math/rand"
	"testing"
)

func reset(t *testing.T) {
	legacyTrustPreferences = map[string][]*LegacyTrustPreference{}
}

// check that reading a trust preference from a config succeeds
func TestInitializeLegacyTrustPreferences(t *testing.T) {
	reset(t)
	InitializeLegacyTrustPreferences("embedded/unit_test/validation/config.json")
	legacyTrustPreference := legacyTrustPreferences["microsoft.com"]
	if len(legacyTrustPreference) != 1 {
		log.Fatalf("wanted: %d, got %d", 1, len(legacyTrustPreference))
	}

	if legacyTrustPreference[0].CASetIdentifier != "Microsoft CA" {
		log.Fatalf("wanted: %s, got %s", "Microsoft CA", legacyTrustPreference[0].CASetIdentifier)

	}

	if len(legacyTrustPreference[0].CASubjectNames) != 2 {
		log.Fatalf("wanted: %d, got %d", 2, len(legacyTrustPreference[0].CASubjectNames))
	}

	if legacyTrustPreference[0].TrustLevel != 1 {
		log.Fatalf("wanted: %d, got %d", 1, legacyTrustPreference[0].TrustLevel)

	}

	legacyTrustPreference = legacyTrustPreferences["bing.com"]
	if len(legacyTrustPreference) != 2 {
		log.Fatalf("wanted: %d, got %d", 2, len(legacyTrustPreference))
	}

	if legacyTrustPreference[0].CASetIdentifier != "US CA" {
		log.Fatalf("wanted: %s, got %s", "US CA", legacyTrustPreference[0].CASetIdentifier)

	}

	if len(legacyTrustPreference[0].CASubjectNames) != 6 {
		log.Fatalf("wanted: %d, got %d", 6, len(legacyTrustPreference[0].CASubjectNames))
	}

	if legacyTrustPreference[0].TrustLevel != 2 {
		log.Fatalf("wanted: %d, got %d", 2, legacyTrustPreference[0].TrustLevel)

	}

	if legacyTrustPreference[1].CASetIdentifier != "Microsoft CA" {
		log.Fatalf("wanted: %s, got %s", "Microsoft CA", legacyTrustPreference[0].CASetIdentifier)

	}

	if len(legacyTrustPreference[1].CASubjectNames) != 2 {
		log.Fatalf("wanted: %d, got %d", 2, len(legacyTrustPreference[0].CASubjectNames))
	}

	if legacyTrustPreference[1].TrustLevel != 1 {
		log.Fatalf("wanted: %d, got %d", 1, legacyTrustPreference[0].TrustLevel)

	}
}

// check that the trust level is computed correctly
func TestSimpleChainTrustLevel(t *testing.T) {
	reset(t)
	InitializeLegacyTrustPreferences("embedded/unit_test/validation/config_simplechain.json")

	chain, _ := testSimpleChainCreate(t, nil, nil)
	chainRev := []*x509.Certificate{chain[2], chain[1], chain[0]}
	trustLevel, _, _, _ := ComputeChainTrustLevelForDomain("leaf1", chainRev)
	if trustLevel != 1 {
		log.Fatalf("wanted: %d, got %d", 1, trustLevel)

	}

	reset(t)
	InitializeLegacyTrustPreferences("embedded/unit_test/validation/config_simplechain_2.json")
	trustLevel, _, _, _ = ComputeChainTrustLevelForDomain("leaf1", chainRev)
	if trustLevel != 2 {
		log.Fatalf("wanted: %d, got %d", 2, trustLevel)

	}
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
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, _ := pem.Decode(pemBytes)
	certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, err = cacheFileSystem.ReadFile("embedded/unit_test/cache/root_privatekeys/root_privatekey.pem")
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, _ = pem.Decode(pemBytes)
	privateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certificateChain = append(certificateChain, certificate)
	privateKeys = append(privateKeys, privateKey)

	// create first certificate chain

	// create intermediate CA
	parent := certificate
	parentSigner := privateKey

	template, err := CreateCertificateTemplate(big.NewInt(int64(1)), []string{"intmCA1"}, 1, 1, 1, 1, true, parent, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(1))))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err = CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(0))))
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, _ = pem.Decode(pemBytes)
	certificate, err = x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	certificateChain = append(certificateChain, certificate)
	privateKeys = append(privateKeys, privateKey)

	// create leaf certificate
	parent = certificate
	parentSigner = privateKey
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(2))))
	if err != nil {
		t.Fatal(err)
	}
	template, err = CreateCertificateTemplate(big.NewInt(int64(2)), []string{"leaf1"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, err = CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(0))))
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, _ = pem.Decode(pemBytes)
	certificate, err = x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certificateChain = append(certificateChain, certificate)
	privateKeys = append(privateKeys, privateKey)

	// create second certificate chain with same leaf DNSName
	// create intermediate CA
	parent = certificateChain[0]
	parentSigner = privateKeys[0]

	template, err = CreateCertificateTemplate(big.NewInt(int64(1)), []string{"intmCA2"}, 1, 1, 1, 1, true, parent, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(1))))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err = CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(0))))
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, _ = pem.Decode(pemBytes)
	certificate, err = x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	certificateChain = append(certificateChain, certificate)
	privateKeys = append(privateKeys, privateKey)

	// create leaf certificate
	parent = certificate
	parentSigner = privateKey
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(3))))
	if err != nil {
		t.Fatal(err)
	}
	template, err = CreateCertificateTemplate(big.NewInt(int64(2)), []string{"leaf1"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, err = CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(0))))
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, _ = pem.Decode(pemBytes)
	certificate, err = x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
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
	InitializeLegacyTrustPreferences("embedded/unit_test/validation/config_simplechain.json")
	cc, _ := testTwoChainsSameLeafDNSNameCreate(t, nil, nil)

	ccToAddToCache := []*x509.Certificate{cc[4], cc[3]}
	ccToVerify := []*x509.Certificate{cc[2], cc[1], cc[0]}

	dnsName := "leaf1"
	AddCertificatesToCache(ccToAddToCache)
	legacyTrustInfoToVerify := NewLegacyTrustInfo(dnsName, ccToVerify)
	VerifyLegacy(legacyTrustInfoToVerify)
	if legacyTrustInfoToVerify.EvaluationResult != SUCCESS {
		log.Fatalf("wanted: %d, got %d", SUCCESS, legacyTrustInfoToVerify.EvaluationResult)

	}
}

// check that connection is accepted if there are no
// cached certificate chains for the domain
func TestVerifyUncached(t *testing.T) {
	reset(t)
	resetCache(t)
	cc, _ := testTwoChainsSameLeafDNSNameCreate(t, nil, nil)
	trustStoreDir := "embedded/unit_test/cache/root_certificates"
	InitializeCache(trustStoreDir)
	InitializeLegacyTrustPreferences("embedded/unit_test/validation/config.json")

	ccToVerify := []*x509.Certificate{cc[2], cc[1], cc[0]}

	dnsName := "leaf1"
	legacyTrustInfoToVerify := NewLegacyTrustInfo(dnsName, ccToVerify)
	trustLevel, _, _, _ := ComputeChainTrustLevelForDomain("leaf1", ccToVerify)
	if trustLevel != 0 {
		log.Fatalf("wanted: %d, got %d", 1, trustLevel)

	}

	VerifyLegacy(legacyTrustInfoToVerify)
	if legacyTrustInfoToVerify.EvaluationResult != SUCCESS {
		log.Fatalf("wanted: %d, got %d", SUCCESS, legacyTrustInfoToVerify.EvaluationResult)
	}
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
	InitializeLegacyTrustPreferences("embedded/unit_test/validation/config_lower_different.json")

	ccToAddToCache := []*x509.Certificate{cc[4], cc[3]}
	ccToVerify := []*x509.Certificate{cc[2], cc[1], cc[0]}
	dnsName := "leaf1"
	AddCertificatesToCache(ccToAddToCache)
	legacyTrustInfoToVerify := NewLegacyTrustInfo(dnsName, ccToVerify)
	VerifyLegacy(legacyTrustInfoToVerify)
	if legacyTrustInfoToVerify.EvaluationResult != FAILURE {
		log.Fatalf("wanted: %d, got %d", FAILURE, legacyTrustInfoToVerify.EvaluationResult)

	}
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
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, _ := pem.Decode(pemBytes)
	certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, err = cacheFileSystem.ReadFile("embedded/unit_test/cache/root_privatekeys/root_privatekey.pem")
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, _ = pem.Decode(pemBytes)
	privateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certificateChain = append(certificateChain, certificate)
	privateKeys = append(privateKeys, privateKey)

	// create first certificate chain

	// create intermediate CA
	parent := certificate
	parentSigner := privateKey

	template, err := CreateCertificateTemplate(big.NewInt(int64(1)), []string{"intmCA1"}, 1, 1, 1, 1, true, parent, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(1))))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err = CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(0))))
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, _ = pem.Decode(pemBytes)
	certificate, err = x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	certificateChain = append(certificateChain, certificate)
	privateKeys = append(privateKeys, privateKey)

	// create leaf certificate
	parent = certificate
	parentSigner = privateKey
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(2))))
	if err != nil {
		t.Fatal(err)
	}
	template, err = CreateCertificateTemplate(big.NewInt(int64(2)), []string{"leaf1"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, err = CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(0))))
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, _ = pem.Decode(pemBytes)
	certificate, err = x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certificateChain = append(certificateChain, certificate)
	privateKeys = append(privateKeys, privateKey)

	// create second certificate chain with same leaf DNSName
	// create intermediate CA
	parent = certificateChain[0]
	parentSigner = privateKeys[0]

	template, err = CreateCertificateTemplate(big.NewInt(int64(1)), []string{"intmCA2"}, 1, 1, 1, 1, true, parent, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(1))))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err = CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(0))))
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, _ = pem.Decode(pemBytes)
	certificate, err = x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	certificateChain = append(certificateChain, certificate)
	privateKeys = append(privateKeys, privateKey)

	// create leaf certificate
	parent = certificate
	parentSigner = privateKey
	privateKey = privateKeys[2]

	template, err = CreateCertificateTemplate(big.NewInt(int64(2)), []string{"leaf1"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, err = CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(0))))
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, _ = pem.Decode(pemBytes)
	certificate, err = x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
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
	InitializeLegacyTrustPreferences("embedded/unit_test/validation/config_lower_different.json")

	cc, _ := testTwoChainsSameLeafSameSKIDNSNameCreate(t, nil, nil)
	ccToAddToCache := []*x509.Certificate{cc[4], cc[3]}
	ccToVerify := []*x509.Certificate{cc[2], cc[1], cc[0]}
	dnsName := "leaf1"
	AddCertificatesToCache(ccToAddToCache)
	legacyTrustInfoToVerify := NewLegacyTrustInfo(dnsName, ccToVerify)
	VerifyLegacy(legacyTrustInfoToVerify)
	if legacyTrustInfoToVerify.EvaluationResult != SUCCESS {
		log.Fatalf("wanted: %d, got %d", SUCCESS, legacyTrustInfoToVerify.EvaluationResult)

	}
}

// check that connection chain with higher trust level than
// all cached certificate chains are accepted.
func TestVerifyHigher(t *testing.T) {
	reset(t)
	resetCache(t)
	trustStoreDir := "embedded/unit_test/cache/root_certificates"
	cc, _ := testTwoChainsSameLeafDNSNameCreate(t, nil, nil)
	InitializeCache(trustStoreDir)
	InitializeLegacyTrustPreferences("embedded/unit_test/validation/config_higher.json")

	ccToAddToCache := []*x509.Certificate{cc[4], cc[3]}
	ccToVerify := []*x509.Certificate{cc[2], cc[1], cc[0]}
	dnsName := "leaf1"
	AddCertificatesToCache(ccToAddToCache)

	legacyTrustInfoToVerify := NewLegacyTrustInfo(dnsName, ccToVerify)
	VerifyLegacy(legacyTrustInfoToVerify)
	if legacyTrustInfoToVerify.EvaluationResult != SUCCESS {
		log.Fatalf("wanted: %d, got %d", SUCCESS, legacyTrustInfoToVerify.EvaluationResult)
	}
}
