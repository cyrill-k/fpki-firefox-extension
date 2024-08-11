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

// (root -> intmCA3 -> c.com)
// (root -> intmCA3 -> b.com)

func testLazyEvaluationChain(t *testing.T, chain []*x509.Certificate, keys []*rsa.PrivateKey) ([]*x509.Certificate, []*rsa.PrivateKey) {
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
	// create intermediate CA 1
	parent := certificate
	parentSigner := privateKey
	template, err := CreateCertificateTemplate(big.NewInt(int64(1)), []string{"intmCA3"}, 1, 1, 1, 1, true, parent, x509.SHA256WithRSA)

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

	// create leaf certificates
	// a.com
	parent = certificate
	parentSigner = privateKey
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(2))))
	if err != nil {
		t.Fatal(err)
	}
	template, err = CreateCertificateTemplate(big.NewInt(int64(2)), []string{"c.com"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
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
	// b.com
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(2))))
	if err != nil {
		t.Fatal(err)
	}
	template, err = CreateCertificateTemplate(big.NewInt(int64(5)), []string{"b.com"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
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

// check that after pruning invalid certificate chain,
// legacy validation succeeds
func TestSuccessAfterPrune(t *testing.T) {
	trustStoreDir := "embedded/unit_test/cache/root_certificates"
	cc, _ := testNameconstraintsChain(t, nil, nil)

	// creates following invalid chain:
	// // (root -> intmCA1(constraint a.com, b.com) -> intmCA2 (constraint b.com, c.com) -> c.com
	nameConstraintChain := []*x509.Certificate{cc[0], cc[1], cc[2], cc[5]}

	resetCache(t)
	InitializeCache(trustStoreDir)
	InitializeLegacyTrustPreferences("embedded/unit_test/validation/config_lazy_evaluation.json")
	AddCertificatesToCache(nameConstraintChain)

	// add valid chain, but above invalid chain is more trusted
	// => invalid chain must be filtered out during lazy evaluation
	cc, _ = testLazyEvaluationChain(nil, nil, nil)
	chainCCom := []*x509.Certificate{cc[2], cc[1], cc[0]}

	legacyTrustInfoToVerify := NewLegacyTrustInfo("c.com", chainCCom)
	VerifyLegacy(legacyTrustInfoToVerify)
	if legacyTrustInfoToVerify.EvaluationResult != SUCCESS {
		log.Fatalf("wanted: %d, got %d", SUCCESS, legacyTrustInfoToVerify.EvaluationResult)

	}
}

// (root -> intmCA4 -> c.com)
func testLazyEvaluationChain1(t *testing.T, chain []*x509.Certificate, keys []*rsa.PrivateKey) ([]*x509.Certificate, []*rsa.PrivateKey) {
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
	// create intermediate CA 1
	parent := certificate
	parentSigner := privateKey
	template, err := CreateCertificateTemplate(big.NewInt(int64(1)), []string{"intmCA4"}, 1, 1, 1, 1, true, parent, x509.SHA256WithRSA)

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

	// create leaf certificates
	// c.com
	parent = certificate
	parentSigner = privateKey
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(5))))
	if err != nil {
		t.Fatal(err)
	}
	template, err = CreateCertificateTemplate(big.NewInt(int64(2)), []string{"c.com"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
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

// check that if the name constrained certificate chain is valid,
// it does not get prunedd
func TestNothingPruned(t *testing.T) {
	trustStoreDir := "embedded/unit_test/cache/root_certificates"
	cc, _ := testNameconstraintsChain(t, nil, nil)
	nameConstraintChain := []*x509.Certificate{cc[0], cc[1], cc[2], cc[4]}

	resetCache(t)
	InitializeCache(trustStoreDir)
	InitializeLegacyTrustPreferences("embedded/unit_test/validation/config_lazy_evaluation.json")
	AddCertificatesToCache(nameConstraintChain)

	cc, _ = testLazyEvaluationChain(nil, nil, nil)
	chainBCom := []*x509.Certificate{cc[3], cc[1], cc[0]}

	// name constraint chain is valid and therefore does not get pruned
	legacyTrustInfoToVerify := NewLegacyTrustInfo("b.com", chainBCom)
	VerifyLegacy(legacyTrustInfoToVerify)
	// as the name constraint chain is more trusted than the chain to verify
	// legacy validation must fail
	if legacyTrustInfoToVerify.EvaluationResult != FAILURE {
		log.Fatalf("wanted: %d, got %d", FAILURE, legacyTrustInfoToVerify.EvaluationResult)
	}
}

// check that if after pruning, there is still another higher
// trusted certificate chain, validation fails
func TestFailureAfterPrune(t *testing.T) {
	trustStoreDir := "embedded/unit_test/cache/root_certificates"
	cc, _ := testNameconstraintsChain(t, nil, nil)
	nameConstraintChain := []*x509.Certificate{cc[0], cc[1], cc[2], cc[5]}
	cc, _ = testLazyEvaluationChain1(t, nil, nil)
	resetCache(t)
	InitializeCache(trustStoreDir)
	InitializeLegacyTrustPreferences("embedded/unit_test/validation/config_lazy_evaluation_2.json")
	// add invalid, but highest trusted chain to cache (name constraint cache, gets pruned)
	AddCertificatesToCache(nameConstraintChain)
	// add 2nd trusted certificate chain to cache, does not get pruned
	AddCertificatesToCache(cc)

	// validate least trusted chain => should fail, as after pruning,
	// there is still a higher trusted chain
	cc, _ = testLazyEvaluationChain(nil, nil, nil)
	chainCCom := []*x509.Certificate{cc[2], cc[1], cc[0]}
	legacyTrustInfoToVerify := NewLegacyTrustInfo("c.com", chainCCom)
	VerifyLegacy(legacyTrustInfoToVerify)
	if legacyTrustInfoToVerify.EvaluationResult != FAILURE {
		log.Fatalf("wanted: %d, got %d", FAILURE, legacyTrustInfoToVerify.EvaluationResult)
	}
}

// check that if chain is the highest trusted chain after pruning
// invalid chains, legacy validation succeeds
func TestSuccessAfterPruneNonEmpty(t *testing.T) {
	trustStoreDir := "embedded/unit_test/cache/root_certificates"
	cc, _ := testNameconstraintsChain(t, nil, nil)
	nameConstraintChain := []*x509.Certificate{cc[0], cc[1], cc[2], cc[5]}
	cc, _ = testLazyEvaluationChain1(t, nil, nil)
	resetCache(t)
	InitializeCache(trustStoreDir)
	InitializeLegacyTrustPreferences("embedded/unit_test/validation/config_lazy_evaluation_3.json")
	// invalid highest trusted name constraint chain
	AddCertificatesToCache(nameConstraintChain)
	// least trusted valid chain (remains after pruning)
	AddCertificatesToCache(cc)

	// chain is more trusted than the chain remaining after pruning
	cc, _ = testLazyEvaluationChain(nil, nil, nil)
	chainCCom := []*x509.Certificate{cc[2], cc[1], cc[0]}
	legacyTrustInfoToVerify := NewLegacyTrustInfo("c.com", chainCCom)
	VerifyLegacy(legacyTrustInfoToVerify)
	if legacyTrustInfoToVerify.EvaluationResult != SUCCESS {
		log.Fatalf("wanted: %d, got %d", SUCCESS, legacyTrustInfoToVerify.EvaluationResult)
	}
}
