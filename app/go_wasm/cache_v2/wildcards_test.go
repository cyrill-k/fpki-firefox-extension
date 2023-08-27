package cache_v2

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"math/rand"
	"testing"
)

// 2 chains
// (root -> intmCA1 -> a.ethz.ch)
// (root -> intmCA2 -> *.ethz.ch)
func testSimpleChainWithWildcardCreate(t *testing.T, chain []*x509.Certificate, keys []*rsa.PrivateKey) ([]*x509.Certificate, []*rsa.PrivateKey) {
	var certificateChain []*x509.Certificate
	var privateKeys []*rsa.PrivateKey
	if chain != nil {
		certificateChain = chain
	}
	if keys != nil {
		privateKeys = keys
	}

	/*
		// code to generate root
		privateKey, err := CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(0))))
		if err != nil {
			t.Fatal(err)
		}

		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		p := EncodePEM(privateKeyBytes, "PRIVATE KEY")
		err = os.WriteFile("embedded/unit_test/root_privatekey.pem", p, 0777)
		if err != nil {
			return nil, nil
		}
		template, err := CreateCertificateTemplate(big.NewInt(int64(0)), "root", 1, 1, 1, 1, true, nil, x509.SHA256WithRSA)
		if err != nil {
			t.Fatal(err)
		}

		pemBytes, err := CreateCertificate(template, privateKey.Public(), template, privateKey, rand.New(rand.NewSource(int64(0))))
		if err != nil {
			t.Fatal(err)
		}

		err = os.WriteFile("embedded/unit_test/root_certificate.pem", pemBytes, 0777)
		if err != nil {
			t.Fatal(err)
		}
	*/

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
	template, err = CreateCertificateTemplate(big.NewInt(int64(2)), []string{"a.ethz.ch"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
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

	// create second leaf certificate valid for a.ethz.ch, but with a wildcard
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(2))))
	if err != nil {
		t.Fatal(err)
	}
	template, err = CreateCertificateTemplate(big.NewInt(int64(2)), []string{"*.ethz.ch"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
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

// check that a query for a.ethz.ch also returns chains
// ending with *.ethz.ch
func TestWildcardFound(t *testing.T) {

	trustStoreDir := "embedded/unit_test/cache/root_certificates"

	chain, _ := testSimpleChainWithWildcardCreate(t, nil, nil)
	resetCache(t)
	InitializeCache(trustStoreDir)
	AddCertificatesToCache(chain[1:])
	chains := GetCertificateChainsForDomain("a.ethz.ch")
	verifyNrChainsAndChainLength(t, chains, 2, []int{3, 3})
	resetCache(t)

}
