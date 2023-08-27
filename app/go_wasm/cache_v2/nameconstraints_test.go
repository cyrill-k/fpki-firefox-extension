package cache_v2

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"math/rand"
	"os"
	"testing"
)

// NOTE: execute this test as follows: go test -run=TestLeafs -v

// (root -> intmCA1(constraint a.com, b.com) -> intmCA2 (constraint b.com, c.com)
// create leafs a.com, b.com, c.com
func testNameconstraintsChain(t *testing.T, chain []*x509.Certificate, keys []*rsa.PrivateKey) ([]*x509.Certificate, []*rsa.PrivateKey) {
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

	template, err := CreateCertificateTemplate(big.NewInt(int64(1)), []string{"intmCA1"}, 1, 1, 1, 1, true, parent, x509.SHA256WithRSA)
	nameConstraints := []string{"intmCA1", "intmCA2", "a.com", "b.com"}
	template.PermittedDNSDomains = nameConstraints
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

	// create intermediate CA 2
	parent = certificate
	parentSigner = privateKey

	template, err = CreateCertificateTemplate(big.NewInt(int64(1)), []string{"intmCA2"}, 1, 1, 1, 1, true, parent, x509.SHA256WithRSA)
	nameConstraints = []string{"intmCA2", "b.com", "c.com"}
	template.PermittedDNSDomains = nameConstraints
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

	// create leaf certificates

	// a.com
	parent = certificate
	parentSigner = privateKey
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(2))))
	if err != nil {
		t.Fatal(err)
	}
	template, err = CreateCertificateTemplate(big.NewInt(int64(2)), []string{"a.com"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
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
	template, err = CreateCertificateTemplate(big.NewInt(int64(2)), []string{"b.com"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
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

	// c.com
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

	return certificateChain, privateKeys
}

// check that name constraints are only checked at leaf
// level
func TestCA2(t *testing.T) {

	trustStoreDir := "tmp_trust_root/"
	os.Mkdir(trustStoreDir, 0777)

	chain, _ := testNameconstraintsChain(t, nil, nil)

	rootCertPool := x509.NewCertPool()
	rootCertPool.AddCert(chain[0])

	intmCertPool := x509.NewCertPool()
	intmCertPool.AddCert(chain[1])

	verifyOpts := x509.VerifyOptions{
		Roots:         rootCertPool,
		Intermediates: intmCertPool,
	}

	_, err := chain[2].Verify(verifyOpts)
	if err != nil {
		t.Fatal(err)
	}

	os.RemoveAll(trustStoreDir)

}

func testLeaf(t *testing.T, leafIndex int, verifyOpts x509.VerifyOptions, chain []*x509.Certificate) {

	_, err := chain[leafIndex].Verify(verifyOpts)
	if err != nil {
		t.Log(err)
	}
}

// demonstrate that only b.com passes validation
func TestLeafs(t *testing.T) {

	trustStoreDir := "tmp_trust_root/"
	os.Mkdir(trustStoreDir, 0777)

	chain, _ := testNameconstraintsChain(t, nil, nil)

	rootCertPool := x509.NewCertPool()
	rootCertPool.AddCert(chain[0])

	intmCertPool := x509.NewCertPool()
	intmCertPool.AddCert(chain[1])
	intmCertPool.AddCert(chain[2])

	verifyOpts := x509.VerifyOptions{
		Roots:         rootCertPool,
		Intermediates: intmCertPool,
	}

	testLeaf(t, 3, verifyOpts, chain)
	testLeaf(t, 4, verifyOpts, chain)
	testLeaf(t, 5, verifyOpts, chain)

	os.RemoveAll(trustStoreDir)
}
