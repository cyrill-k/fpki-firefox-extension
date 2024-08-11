package cache_v2

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"os"
	"testing"
	"time"
)

const TRUST_STORE_DIR = "embedded/ca-certificates"

func resetCache(t *testing.T) {
	certificateCache = map[string]*CertificateCacheEntry{}
	subjectSKICache = map[string]*SubjectSKICacheEntry{}
	dnsNameCache = map[string][]string{}
}

func contains[T comparable](l []T, e T) bool {
	for _, v := range l {
		if v == e {
			return true
		}
	}
	return false
}

// test that cache initialization works as expected
func TestInitializeCache(t *testing.T) {
	resetCache(t)
	files, err := os.ReadDir(TRUST_STORE_DIR)
	if err != nil {
		t.Fatal(err)
	}
	nCertificates := InitializeCache(TRUST_STORE_DIR)
	if len(files) != nCertificates {
		log.Fatalf("wanted: %d, got %d", len(files), nCertificates)
	}
}

// test that GetMissingCertificateHashesList returns exactly
// the missing hashes
func TestGetMissingCertificateHashesList(t *testing.T) {
	resetCache(t)
	InitializeCache(TRUST_STORE_DIR)

	var certificateHashes []string
	// add 2 missing "hashes"
	certificateHashes = append(certificateHashes, "42", "4242")

	// add certificate hashes of certificates in the cache to the input
	// (those are not missing)
	files, err := ioutil.ReadDir(TRUST_STORE_DIR)
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range files {

		// parse trust root certificate
		fileBytes, err := cacheFileSystem.ReadFile(TRUST_STORE_DIR + "/" + file.Name())
		if err != nil {
			log.Fatal(err)
		}
		var block *pem.Block
		block, rem := pem.Decode(fileBytes)
		if len(rem) > 0 {
			log.Fatalf("Error during parsing of trust root PEM: %s", file.Name())
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		certificateHashes = append(certificateHashes, GetRawCertificateHash(certificate))
	}

	// add another 2 missing "hashes"
	certificateHashes = append(certificateHashes, "TEST", "TESTTEST")

	missingCertificates := GetMissingCertificateHashesList(certificateHashes)

	if len(missingCertificates) != 4 {
		t.Fatalf("wanted %d, got %d", 4, len(missingCertificates))
	}
}

// creates a simple certificate chain of 3 certificates (root -> intmCA1 -> leaf1)
func testSimpleChainCreate(t *testing.T, chain []*x509.Certificate, keys []*rsa.PrivateKey) ([]*x509.Certificate, []*rsa.PrivateKey) {
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
		// uncomment this in case root certificate for testing expires

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

// check that the expected number of chains are found, and that the
// chains have the expected length
func verifyNrChainsAndChainLength(t *testing.T, chains []*CertificateChainInfo, nChains int, chainLengths []int) {
	if len(chains) != nChains {
		log.Fatalf("wanted: %d chains, got %d", nChains, len(chains))
	}
	for i := 0; i < len(chains); i++ {
		chainLength := len(chains[i].certificateChain)
		var newChainLengths []int
		found := false
		var j int
		for j = 0; j < len(chainLengths); j++ {
			if chainLengths[j] == chainLength {
				found = true
				break
			} else {
				newChainLengths = append(newChainLengths, chainLengths[j])
			}
		}
		if !found {
			log.Fatalf("chain lengths did not fit")
		}
		for ; j < len(chainLengths)-1; j++ {
			newChainLengths = append(newChainLengths, chainLengths[j+1])
		}
		chainLengths = newChainLengths
	}
}

// check that for a single chain, this chain is found
// and has the correct length
// also vary the order in which certificates are added to the cache
// and check that it does not change the outcome
func TestSimpleChain(t *testing.T) {
	trustStoreDir := "embedded/unit_test/cache/root_certificates"

	chain, _ := testSimpleChainCreate(t, nil, nil)
	resetCache(t)
	InitializeCache(trustStoreDir)
	AddCertificatesToCache(chain[1:])

	chains := GetCertificateChainsForDomain("leaf1")
	verifyNrChainsAndChainLength(t, chains, 1, []int{3})

	resetCache(t)
	InitializeCache(trustStoreDir)
	chainReordered := []*x509.Certificate{chain[2], chain[1]}
	AddCertificatesToCache(chainReordered)

	chains = GetCertificateChainsForDomain("leaf1")
	verifyNrChainsAndChainLength(t, chains, 1, []int{3})
}

// two chains: (root -> intmCA1 -> leaf1), (root -> intmCA1 -> leaf2)
func testParentAndCertificateCachedCreate(t *testing.T) ([]*x509.Certificate, []*rsa.PrivateKey) {
	certificateChain, privateKeys := testSimpleChainCreate(t, nil, nil)

	parent := certificateChain[len(certificateChain)-2]
	parentSigner := privateKeys[len(privateKeys)-2]

	// create a new leaf with the same chain as leaf1
	template, err := CreateCertificateTemplate(big.NewInt(int64(3)), []string{"leaf2"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(1))))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(0))))
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, _ := pem.Decode(pemBytes)
	certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	certificateChain = append(certificateChain, certificate)
	privateKeys = append(privateKeys, privateKey)

	return certificateChain, privateKeys

}

// add all certificates of first chain, then add leaf2
// and check that the certificate chain for leaf2 can be reconstructed
func TestParentAndCertificateCached(t *testing.T) {
	trustStoreDir := "embedded/unit_test/cache/root_certificates"

	chain, _ := testParentAndCertificateCachedCreate(t)
	resetCache(t)
	InitializeCache(trustStoreDir)
	AddCertificatesToCache(chain[1 : len(chain)-1])
	AddCertificatesToCache([]*x509.Certificate{chain[len(chain)-1]})

	chains := GetCertificateChainsForDomain("leaf2")
	verifyNrChainsAndChainLength(t, chains, 1, []int{3})
}

// 3 chains: intmCA1 has same <Subject, SKI> as intmCA1'
// (root -> intmCA1 -> leaf1), (root -> intmCA1' -> leaf2), (root -> intmCA1 -> leaf3)
func testParentCachedButDifferentCertificateCreate(t *testing.T) ([][]*x509.Certificate, [][]*rsa.PrivateKey) {
	certificateChain, privateKeys := testSimpleChainCreate(t, nil, nil)
	rootCertificate := certificateChain[0]
	rootPrivateKey := privateKeys[0]

	certificateChain1 := []*x509.Certificate{rootCertificate}
	privateKeys1 := []*rsa.PrivateKey{rootPrivateKey}

	// create a second certificate chain

	// create an intermediate CA with same subject and public key
	parent := rootCertificate
	parentSigner := rootPrivateKey

	template, err := CreateCertificateTemplate(big.NewInt(int64(1)), []string{"intmCA1"}, 1, 1, 1, 2, true, parent, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := privateKeys[1]
	pemBytes, err := CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(0))))
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, _ := pem.Decode(pemBytes)
	certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	certificateChain1 = append(certificateChain1, certificate)
	privateKeys1 = append(privateKeys1, privateKey)

	// create a new leaf with the new intermediate CA certificate as parent
	parent = certificate
	parentSigner = privateKey
	template, err = CreateCertificateTemplate(big.NewInt(int64(3)), []string{"leaf2"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
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

	certificateChain1 = append(certificateChain1, certificate)
	privateKeys1 = append(privateKeys1, privateKey)

	// create a third certificate chain differing from the first one
	// only in the leaf certificate
	certificateChain2 := []*x509.Certificate{certificateChain[0], certificateChain[1]}
	privateKeys2 := []*rsa.PrivateKey{privateKeys[0], privateKeys[1]}
	parent = certificateChain2[1]
	parentSigner = privateKeys2[1]
	template, err = CreateCertificateTemplate(big.NewInt(int64(4)), []string{"leaf3"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(4))))
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

	certificateChain2 = append(certificateChain2, certificate)
	privateKeys2 = append(privateKeys2, privateKey)

	return [][]*x509.Certificate{certificateChain, certificateChain2, certificateChain1}, [][]*rsa.PrivateKey{privateKeys, privateKeys2, privateKeys1}

}

// check that the chain consists of the expected subjects
func verifyChainsDNSNames(t *testing.T, chains []*CertificateChainInfo, chainDNSNames [][]string) {
	for i, chainInfo := range chains {
		for j, certificate := range chainInfo.certificateChain {
			if !contains(certificate.DNSNames, chainDNSNames[i][j]) {
				fmt.Println(certificate.DNSNames)
				t.Fatal("certificate chain incorrect")

			}
		}
	}
}

// ensure that after adding the certificates, all leaf1 and leaf2
// both have 2 chains of length 3 with expected subjects.
// also vary order of cache additions
func TestParentCachedButDifferentCertificate(t *testing.T) {
	trustStoreDir := "embedded/unit_test/cache/root_certificates"

	certificateChains, _ := testParentCachedButDifferentCertificateCreate(t)

	resetCache(t)
	InitializeCache(trustStoreDir)
	AddCertificatesToCache(certificateChains[0][1:])
	AddCertificatesToCache(certificateChains[1][2:])
	AddCertificatesToCache(certificateChains[2][1:])

	chains := GetCertificateChainsForDomain("leaf2")
	verifyNrChainsAndChainLength(t, chains, 2, []int{3, 3})

	chainDNSNames := [][]string{[]string{"leaf2", "intmCA1", "root"}, []string{"leaf2", "intmCA1", "root"}}
	verifyChainsDNSNames(t, chains, chainDNSNames)

	chains = GetCertificateChainsForDomain("leaf3")
	verifyNrChainsAndChainLength(t, chains, 2, []int{3, 3})

	chainDNSNames = [][]string{[]string{"leaf3", "intmCA1", "root"}, []string{"leaf3", "intmCA1", "root"}}
	verifyChainsDNSNames(t, chains, chainDNSNames)

	// swapping order how certificates of leaf1 get added
	resetCache(t)
	InitializeCache(trustStoreDir)

	leaf1NewOrder := []*x509.Certificate{certificateChains[0][2], certificateChains[0][1]}
	AddCertificatesToCache(leaf1NewOrder)
	AddCertificatesToCache(certificateChains[1][2:])
	AddCertificatesToCache(certificateChains[2][1:])

	chains = GetCertificateChainsForDomain("leaf2")
	verifyNrChainsAndChainLength(t, chains, 2, []int{3, 3})

	chainDNSNames = [][]string{[]string{"leaf2", "intmCA1", "root"}, []string{"leaf2", "intmCA1", "root"}}
	verifyChainsDNSNames(t, chains, chainDNSNames)

	chains = GetCertificateChainsForDomain("leaf3")
	verifyNrChainsAndChainLength(t, chains, 2, []int{3, 3})

	chainDNSNames = [][]string{[]string{"leaf3", "intmCA1", "root"}, []string{"leaf3", "intmCA1", "root"}}
	verifyChainsDNSNames(t, chains, chainDNSNames)

	// swapping order how certificates of leaf2 get added
	resetCache(t)
	InitializeCache(trustStoreDir)

	leaf2NewOrder := []*x509.Certificate{certificateChains[2][2], certificateChains[2][1]}
	AddCertificatesToCache(certificateChains[0][1:])
	AddCertificatesToCache(certificateChains[1][2:])
	AddCertificatesToCache(leaf2NewOrder)

	chains = GetCertificateChainsForDomain("leaf2")
	verifyNrChainsAndChainLength(t, chains, 2, []int{3, 3})

	chainDNSNames = [][]string{[]string{"leaf2", "intmCA1", "root"}, []string{"leaf2", "intmCA1", "root"}}
	verifyChainsDNSNames(t, chains, chainDNSNames)

	chains = GetCertificateChainsForDomain("leaf3")
	verifyNrChainsAndChainLength(t, chains, 2, []int{3, 3})

	chainDNSNames = [][]string{[]string{"leaf3", "intmCA1", "root"}, []string{"leaf3", "intmCA1", "root"}}
	verifyChainsDNSNames(t, chains, chainDNSNames)

	// swapping order of how chains get added
	resetCache(t)
	InitializeCache(trustStoreDir)

	AddCertificatesToCache(leaf2NewOrder)
	AddCertificatesToCache(certificateChains[0][1:])
	AddCertificatesToCache(certificateChains[1][2:])

	chains = GetCertificateChainsForDomain("leaf2")
	verifyNrChainsAndChainLength(t, chains, 2, []int{3, 3})

	chainDNSNames = [][]string{[]string{"leaf2", "intmCA1", "root"}, []string{"leaf2", "intmCA1", "root"}}
	verifyChainsDNSNames(t, chains, chainDNSNames)

	chains = GetCertificateChainsForDomain("leaf3")
	verifyNrChainsAndChainLength(t, chains, 2, []int{3, 3})

	chainDNSNames = [][]string{[]string{"leaf3", "intmCA1", "root"}, []string{"leaf3", "intmCA1", "root"}}
	verifyChainsDNSNames(t, chains, chainDNSNames)

	// swapping order of how chains get added
	resetCache(t)
	InitializeCache(trustStoreDir)

	AddCertificatesToCache(leaf2NewOrder)
	AddCertificatesToCache(leaf1NewOrder)
	AddCertificatesToCache(certificateChains[1][2:])

	chains = GetCertificateChainsForDomain("leaf2")
	verifyNrChainsAndChainLength(t, chains, 2, []int{3, 3})

	chainDNSNames = [][]string{[]string{"leaf2", "intmCA1", "root"}, []string{"leaf2", "intmCA1", "root"}}
	verifyChainsDNSNames(t, chains, chainDNSNames)

	chains = GetCertificateChainsForDomain("leaf3")
	verifyNrChainsAndChainLength(t, chains, 2, []int{3, 3})

	chainDNSNames = [][]string{[]string{"leaf3", "intmCA1", "root"}, []string{"leaf3", "intmCA1", "root"}}
	verifyChainsDNSNames(t, chains, chainDNSNames)

	// swapping order of how chains get added
	resetCache(t)
	InitializeCache(trustStoreDir)

	AddCertificatesToCache(certificateChains[1][1:])
	AddCertificatesToCache(certificateChains[0][2:])
	AddCertificatesToCache(certificateChains[2][1:])

	chains = GetCertificateChainsForDomain("leaf2")
	verifyNrChainsAndChainLength(t, chains, 2, []int{3, 3})

	chainDNSNames = [][]string{[]string{"leaf2", "intmCA1", "root"}, []string{"leaf2", "intmCA1", "root"}}
	verifyChainsDNSNames(t, chains, chainDNSNames)

	chains = GetCertificateChainsForDomain("leaf3")
	verifyNrChainsAndChainLength(t, chains, 2, []int{3, 3})

	chainDNSNames = [][]string{[]string{"leaf3", "intmCA1", "root"}, []string{"leaf3", "intmCA1", "root"}}
	verifyChainsDNSNames(t, chains, chainDNSNames)
}

// 2 chains: (root -> intmCA1 -> leaf1), (root -> intmCA2 -> leaf2)
func testParentUncached(t *testing.T) ([][]*x509.Certificate, [][]*rsa.PrivateKey) {
	certificateChain, privateKeys := testSimpleChainCreate(t, nil, nil)
	rootCertificate := certificateChain[0]
	rootPrivateKey := privateKeys[0]

	certificateChain1 := []*x509.Certificate{rootCertificate}
	privateKeys1 := []*rsa.PrivateKey{rootPrivateKey}

	// create a second certificate chain

	// create an intermediate CA with different subject and public key
	parent := rootCertificate
	parentSigner := rootPrivateKey

	template, err := CreateCertificateTemplate(big.NewInt(int64(1)), []string{"intmCA2"}, 1, 1, 1, 1, true, parent, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(1))))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(0))))
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, _ := pem.Decode(pemBytes)
	certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	certificateChain1 = append(certificateChain1, certificate)
	privateKeys1 = append(privateKeys1, privateKey)

	// create a new leaf with the new intermediate CA certificate as parent
	parent = certificate
	parentSigner = privateKey
	template, err = CreateCertificateTemplate(big.NewInt(int64(3)), []string{"leaf2"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
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

	certificateChain1 = append(certificateChain1, certificate)
	privateKeys1 = append(privateKeys1, privateKey)

	return [][]*x509.Certificate{certificateChain, certificateChain1}, [][]*rsa.PrivateKey{privateKeys, privateKeys1}

}

// check that after adding both certificate chains, each leaf still
// only has a single chain (and it is the expected one)
func TestParentUncached(t *testing.T) {
	trustStoreDir := "embedded/unit_test/cache/root_certificates"

	certificateChains, _ := testParentUncached(t)

	resetCache(t)
	InitializeCache(trustStoreDir)
	AddCertificatesToCache(certificateChains[0][1:])
	AddCertificatesToCache(certificateChains[1][1:])

	chains := GetCertificateChainsForDomain("leaf1")
	verifyNrChainsAndChainLength(t, chains, 1, []int{3})
	chainDNSNames := [][]string{[]string{"leaf1", "intmCA1", "root"}}
	verifyChainsDNSNames(t, chains, chainDNSNames)
	chains = GetCertificateChainsForDomain("leaf2")
	verifyNrChainsAndChainLength(t, chains, 1, []int{3})
	chainDNSNames = [][]string{[]string{"leaf2", "intmCA2", "root"}}
	verifyChainsDNSNames(t, chains, chainDNSNames)

}

// 2 chains:
// (root -> intmCA1 -> intmCA2 -> leaf1)
// (root -> intmCA1' -> intmCA2' -> leaf1)
// intmCA1 == intmCA1', intmCA2 == intmCA2' (same Subject, SKI)
func testSimpleChain2IntmsCreate(t *testing.T, chain []*x509.Certificate, keys []*rsa.PrivateKey) ([]*x509.Certificate, []*rsa.PrivateKey) {
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
	pemBytes, err = CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(1))))
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

	// create intermediate CA
	parent = certificate
	parentSigner = privateKey

	template, err = CreateCertificateTemplate(big.NewInt(int64(2)), []string{"intmCA2"}, 1, 1, 1, 1, true, parent, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err = CreateAndStoreRSAPrivateKey(rand.New(rand.NewSource(int64(2))))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err = CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(2))))
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

	time.Sleep(5 * time.Second)
	// create second certificate chain with same CAs
	// create intermediate CA
	parent = certificateChain[0]
	parentSigner = privateKeys[0]

	template, err = CreateCertificateTemplate(big.NewInt(int64(1)), []string{"intmCA1"}, 1, 1, 1, 1, true, parent, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	privateKey = privateKeys[1]
	pemBytes, err = CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(1))))
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

	// create intermediate CA
	parent = certificate
	parentSigner = privateKey

	template, err = CreateCertificateTemplate(big.NewInt(int64(2)), []string{"intmCA2"}, 1, 1, 1, 1, true, parent, x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	privateKey = privateKeys[2]
	pemBytes, err = CreateCertificate(template, privateKey.Public(), parent, parentSigner, rand.New(rand.NewSource(int64(2))))
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
	template, err = CreateCertificateTemplate(big.NewInt(int64(3)), []string{"leaf1"}, 1, 1, 1, 1, false, parent, x509.SHA256WithRSA)
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

// check that the leaf certificate has all combinations
// of certificate chains
func TestTwoChainsWithTwoIntermediates(t *testing.T) {

	trustStoreDir := "embedded/unit_test/cache/root_certificates"

	certificates, _ := testSimpleChain2IntmsCreate(t, nil, nil)
	certificatesReordered := []*x509.Certificate{certificates[5], certificates[1], certificates[2], certificates[3], certificates[4]}

	resetCache(t)
	InitializeCache(trustStoreDir)
	AddCertificatesToCache(certificatesReordered)

	chains := GetCertificateChainsForDomain("leaf1")
	verifyNrChainsAndChainLength(t, chains, 4, []int{4, 4, 4, 4})
	chainDNSNames := [][]string{[]string{"leaf1", "intmCA2", "intmCA1", "root"},
		[]string{"leaf1", "intmCA2", "intmCA1", "root"},
		[]string{"leaf1", "intmCA2", "intmCA1", "root"},
		[]string{"leaf1", "intmCA2", "intmCA1", "root"}}
	verifyChainsDNSNames(t, chains, chainDNSNames)

}
