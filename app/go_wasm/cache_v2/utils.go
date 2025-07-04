package cache_v2

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"strings"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
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

func minTime(times ...time.Time) (minTime time.Time) {
	for i, t := range times {
		if i == 0 || t.Before(minTime) {
			minTime = t
		}
	}
	return
}

func TransformListToInterfaceType[T any](list []T) []interface{} {
	t := make([]interface{}, len(list))
	for i, e := range list {
		t[i] = e
	}
	return t
}

func TransformNestedListsToInterfaceType[T any](list [][]T) []interface{} {
	t := make([]interface{}, len(list))
	for i, e := range list {
		ti := make([]interface{}, len(e))
		for j, ej := range e {
			ti[j] = ej
		}
		t[i] = ti
	}
	return t
}

func SliceToSet(slice []string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, e := range slice {
		set[e] = struct{}{}
	}
	return set
}

// compute the base64 encoded hash of the base64 encoded payload
func GetPayloadAndHash(b64payload string) ([]byte, string) {
	payload, err := base64.StdEncoding.DecodeString(b64payload)
	if err != nil {
		log.Fatal(err)
	}
	h := sha256.New()
	_, err = h.Write(payload)
	if err != nil {
		log.Fatal(err)
	}
	hash := h.Sum(nil)
	return payload, base64.StdEncoding.EncodeToString(hash)
}

func ReadJsonFileAsMap(filePath string) (map[string]interface{}, error) {
	bytes, err := validationFileSystem.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var jsonMap map[string]interface{}
	json.Unmarshal([]byte(bytes), &jsonMap)
	return jsonMap, nil
}

func PolicyCertDesc(cert *common.PolicyCertificate) string {
	desc := "<"
	if cert.Domain() != "" {
		desc += fmt.Sprintf("domain=%v, ", cert.Domain())
	}
	desc += fmt.Sprintf("canIssue=%v, ", cert.CanIssue)
	desc += fmt.Sprintf("canOwn=%v, ", cert.CanOwn)
	selfSigned, err := IsSelfSignedCertificate(cert)
	if selfSigned && err == nil {
		desc += "self-signed cert, "
	} else {
		desc += "signer hash=" + getIssuerHash(cert) + ", "
	}
	desc += fmt.Sprintf("policy attributes=%+v, ", cert.PolicyAttributes)
	desc += fmt.Sprintf("hash=%s, ", getPolicyHash(cert))
	desc += fmt.Sprintf("immHash=%s, ", getImmutablePolicyHash(cert))
	desc += fmt.Sprintf("[%v, %v]", cert.NotBefore, cert.NotAfter)
	return desc + ">"
}

func IsSelfSignedCertificate(p *common.PolicyCertificate) (bool, error) {
	// Remove SPCTs and issuer signature and set the IssuerHash field to nil to simulate a self-signed policy certificate.
	SPCTs, issuerSignature, issuerHash := p.SPCTs, p.IssuerSignature, p.IssuerHash
	p.SPCTs, p.IssuerSignature, p.IssuerHash = nil, nil, nil

	// Serialize and restore previously removed fields.
	serializedPC, err := common.ToJSON(p)
	p.SPCTs, p.IssuerSignature, p.IssuerHash = SPCTs, issuerSignature, issuerHash

	return bytes.Compare(common.SHA256Hash(serializedPC), issuerHash) == 0, err
}

// remove trailing dots from domain names
func normalizeDomain(d string) string {
	return strings.TrimSuffix(d, ".")
}

// checks whether d1 is a subdomain of d2
// assumes that both inputs are valid domains without any wildcards
func isSameOrSubdomain(d1, d2 string) bool {
	d2Suffix := normalizeDomain(d2)
	if len(d2Suffix) > 0 {
		d2Suffix = "." + d2Suffix
	}
	return d1 == d2 || strings.HasSuffix(d1, d2Suffix)
}

func generateWildcardAndParentDomain(dnsName string) []string {
	dnsNameNormalized := normalizeDomain(dnsName)
	components := strings.Split(dnsNameNormalized, ".")
	orderedParentDomains := make([]string, 2*len(components))
	for from := range components {
		orderedParentDomains = append(orderedParentDomains, strings.Join(components[from:], "."))
		orderedParentDomains = append(orderedParentDomains, strings.Join(append([]string{"*"}, components[from+1:]...), "."))
	}
	return orderedParentDomains
}
