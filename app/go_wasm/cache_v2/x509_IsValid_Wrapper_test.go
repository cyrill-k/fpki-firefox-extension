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

	return certificateChain, privateKeys
}

func TestIsValidWrapper(t *testing.T) {

	chain, _ := testSimpleChainCreate(t, nil, nil)
	verifyOpts := &x509.VerifyOptions{}

	err := chain[2].IsValid(x509.LeafCertificate, []*x509.Certificate{}, verifyOpts)
	require.NoError(t, err)

	err = chain[1].IsValid(x509.IntermediateCertificate, []*x509.Certificate{chain[2]}, verifyOpts)
	require.NoError(t, err)

	err = chain[0].IsValid(x509.IntermediateCertificate, []*x509.Certificate{chain[2], chain[1]}, verifyOpts)
	require.NoError(t, err)

}
