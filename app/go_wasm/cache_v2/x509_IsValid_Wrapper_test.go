package cache_v2

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"math/rand"
	"testing"
)

// (root -> intmCA1 -> leaf1)
func testChain(t *testing.T, chain []*x509.Certificate, keys []*rsa.PrivateKey) ([]*x509.Certificate, []*rsa.PrivateKey) {
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

func TestIsValidWrapper(t *testing.T) {

	chain, _ := testSimpleChainCreate(t, nil, nil)
	verifyOpts := &x509.VerifyOptions{}

	err := chain[2].IsValid(x509.LeafCertificate, []*x509.Certificate{}, verifyOpts)
	if err != nil {
		t.Fatal(err)
	}

	err = chain[1].IsValid(x509.IntermediateCertificate, []*x509.Certificate{chain[2]}, verifyOpts)
	if err != nil {
		t.Fatal(err)
	}

	err = chain[0].IsValid(x509.IntermediateCertificate, []*x509.Certificate{chain[2], chain[1]}, verifyOpts)
	if err != nil {
		t.Fatal(err)
	}

}
