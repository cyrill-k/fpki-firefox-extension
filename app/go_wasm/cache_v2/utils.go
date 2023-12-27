package cache_v2

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"math/rand"
	"time"
)

const CERTIFICATE = "CERTIFICATE"

// EncodePEM encodes the content as PEM of type pemType.
func EncodePEM(content []byte, pemType string) []byte {
	block := &pem.Block{
		Type:  pemType,
		Bytes: content,
	}
	return pem.EncodeToMemory(block)
}

// CreateAndStoreRSAPrivateKey creates an RSA private key
func CreateAndStoreRSAPrivateKey(r *rand.Rand) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(r, 2048)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// ValidityPeriod returns a validity period starting
// at time.Now() and ending at
// time.Now + the specified years, months, days and hours.
func ValidityPeriod(years int,
	months int,
	days int,
	hours int) (time.Time, time.Time) {
	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(years, months, days)
	notAfter = notAfter.Add(time.Hour * time.Duration(hours))
	return notBefore, notAfter
}

// CreateCertificateTemplate creates a template for a x509 certificate.
// The validity period starts at time.Now() and ends at
// time.Now() + the specified years, months, days, hours.
// If parent is nil, the issuer and the subject will be
// equivalent.
func CreateCertificateTemplate(serialNr *big.Int,
	dnsNames []string,
	years int,
	months int,
	days int,
	hours int,
	isCA bool,
	parent *x509.Certificate,
	signatureAlgorithm x509.SignatureAlgorithm) (*x509.Certificate, error) {

	subject := pkix.Name{
		SerialNumber: serialNr.String(),
		CommonName:   dnsNames[0],
	}

	// self signed certificate (trust anchor) if parent is nil
	var issuer pkix.Name = subject
	if parent != nil {
		issuer = parent.Subject
	}

	notBefore, notAfter := ValidityPeriod(years, months, days, hours)

	var keyUsage x509.KeyUsage
	if isCA {
		keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		keyUsage = x509.KeyUsageDigitalSignature
	}

	template := &x509.Certificate{

		SerialNumber:          serialNr,
		SignatureAlgorithm:    signatureAlgorithm,
		Issuer:                issuer,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		MaxPathLen:            -1,
		KeyUsage:              keyUsage,
		DNSNames:              dnsNames,
	}
	return template, nil
}

// CreateCertificate creates a x509 certificate binding the public
// key to the information specified in the template.
// The certificate is signed by the parentSigner.
// The certificate is returned in PEM encoding.
func CreateCertificate(template *x509.Certificate,
	publicKey crypto.PublicKey,
	parent *x509.Certificate,
	parentSigner crypto.Signer,
	r *rand.Rand) ([]byte, error) {

	var certBytes []byte
	var err error
	if parent == nil {
		certBytes, err = x509.CreateCertificate(r, template, template, publicKey, parentSigner)
	} else {
		certBytes, err = x509.CreateCertificate(r, template, parent, publicKey, parentSigner)
	}
	if err != nil {
		return nil, err
	}
	pem := EncodePEM(certBytes, CERTIFICATE)
	return pem, nil
}

func maxTime(times ...time.Time) (maxTime time.Time) {
	for i, t := range times {
		if i == 0 || t.After(maxTime) {
			maxTime = t
		}
	}
	return
}
