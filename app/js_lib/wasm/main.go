package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"sync"
	"syscall/js"
	"time"
)

var testHashes = "17:9F:BC:14:8A:3D:D0:0F:D2:4E:A1:34:58:CC:43:BF:A7:F5:9C:81:82:D7:83:A5:13:F6:EB:EC:10:0C:89:24\n87:C7:15:53:44:5E:B3:C3:3C:3E:07:10:71:1B:99:E9:C7:77:3F:04:D9:1A:C3:8A:9F:4C:08:2E:E2:41:01:EA\nB3:7B:68:33:08:7E:9F:04:13:37:A8:07:AA:E0:A4:1A:4E:CD:57:F5:DB:1D:A6:24:9E:C2:97:53:22:B1:5D:55"
var testCertificates = "-----BEGIN CERTIFICATE-----\nMIICHjCCAaSgAwIBAgIRYFlJ4CYuu1X5CneKcflK2GwwCgYIKoZIzj0EAwMwUDEkMCIGA1UECxMbR2xvYmFsU2lnbiBFQ0MgUm9vdCBDQSAtIFI1MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTEyMTExMzAwMDAwMFoXDTM4MDExOTAzMTQwN1owUDEkMCIGA1UECxMbR2xvYmFsU2lnbiBFQ0MgUm9vdCBDQSAtIFI1MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAER0UOlvt9Xb/pOdEh+J8LttV7HpI6SFkc8GIxLcB6KP4ap1yztsyX50XUWPrRd21DosCHZTQKH3rd6zwzocWdTaRvQZU4f8kehOvRnkmSh5SHDDqFSmafnVmTTZdhBoZKo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUPeYpSJvqB8ohREom3m7e0oPQn1kwCgYIKoZIzj0EAwMDaAAwZQIxAOVpEslu28YxuglB4Zf4+/2a4n0Sye18ZNPLBSWLVtmg515dTguDnFt2KaAJJiFqYgIwcdK1j1zqO+F4CYWodZI7yFz9SO8NdCKoCOJuxUnOxwy8p2Fp8fc74SrL+SvzZpA3\n-----END CERTIFICATE-----\n;-----BEGIN CERTIFICATE-----\nMIIDAjCCAomgAwIBAgINAe5fIpVCSQX5AZGo3DAKBggqhkjOPQQDAzBQMSQwIgYDVQQLExtHbG9iYWxTaWduIEVDQyBSb290IENBIC0gUjUxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTgxMTIxMDAwMDAwWhcNMjgxMTIxMDAwMDAwWjBQMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEmMCQGA1UEAxMdR2xvYmFsU2lnbiBFQ0MgT1YgU1NMIENBIDIwMTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATDoRGNZSPhluG7q6bQA11PTe0ZD/xx44QlFam1BM4eLeN+wfgwalsbkjzARCM9si/fnQeKNtKAlgNmNOHTmV3VfwGbocj6+22HVWZuVeX/VeIGoWh1u7Lja/NDE7RsXaCjggEpMIIBJTAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUWHuOdSr+YYCqkEABrtboB0ZuP0gwHwYDVR0jBBgwFoAUPeYpSJvqB8ohREom3m7e0oPQn1kwPgYIKwYBBQUHAQEEMjAwMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI1MDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9vdC1yNS5jcmwwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAoGCCqGSM49BAMDA2cAMGQCMC4lzZGQw5mpNZBmztq8huxKf9/tRUJ5yLI4q6YU+i2fjF2FRBNA64EBmljA7dkSOwIwL9qYB0APhsLmV0LhknrzHZVvtqzg7NQaIV18BEIDZQgK3gjxYzADjHSH5uk4mCdW\n-----END CERTIFICATE-----\n;-----BEGIN CERTIFICATE-----\nMIIHNjCCBrygAwIBAgIMcdk8EXfhtkjduL9UMAoGCCqGSM49BAMDMFAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSYwJAYDVQQDEx1HbG9iYWxTaWduIEVDQyBPViBTU0wgQ0EgMjAxODAeFw0yMjA3MDUwNjQyMDJaFw0yMzA4MDYwNTE2MDFaMIGnMQswCQYDVQQGEwJDTjEQMA4GA1UECBMHYmVpamluZzEQMA4GA1UEBxMHYmVpamluZzElMCMGA1UECxMcc2VydmljZSBvcGVyYXRpb24gZGVwYXJ0bWVudDE5MDcGA1UEChMwQmVpamluZyBCYWlkdSBOZXRjb20gU2NpZW5jZSBUZWNobm9sb2d5IENvLiwgTHRkMRIwEAYDVQQDEwliYWlkdS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT3pi9GYo79uACxAHjUYA5vlc4n1jWwbPI2elIkx/+cDO1lYmpwLN6IchHD3fjSOJTSIXeEGEI/yJZuqQWE7Rpfo4IFIjCCBR4wDgYDVR0PAQH/BAQDAgeAMIGOBggrBgEFBQcBAQSBgTB/MEQGCCsGAQUFBzAChjhodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc2VjY292c3NsY2EyMDE4LmNydDA3BggrBgEFBQcwAYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vZ3NlY2NvdnNzbGNhMjAxODBWBgNVHSAETzBNMEEGCSsGAQQBoDIBFDA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAIBgZngQwBAgIwCQYDVR0TBAIwADA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2dzZWNjb3Zzc2xjYTIwMTguY3JsMIIDYQYDVR0RBIIDWDCCA1SCCWJhaWR1LmNvbYISY2xpY2suaG0uYmFpZHUuY29tghBjbS5wb3MuYmFpZHUuY29tghBsb2cuaG0uYmFpZHUuY29tghR1cGRhdGUucGFuLmJhaWR1LmNvbYIQd24ucG9zLmJhaWR1LmNvbYIIKi45MS5jb22CCyouYWlwYWdlLmNuggwqLmFpcGFnZS5jb22CDSouYXBvbGxvLmF1dG+CCyouYmFpZHUuY29tgg4qLmJhaWR1YmNlLmNvbYISKi5iYWlkdWNvbnRlbnQuY29tgg4qLmJhaWR1cGNzLmNvbYIRKi5iYWlkdXN0YXRpYy5jb22CDiouYmFpZnViYW8uY29tgg8qLmJjZS5iYWlkdS5jb22CDSouYmNlaG9zdC5jb22CCyouYmRpbWcuY29tgg4qLmJkc3RhdGljLmNvbYINKi5iZHRqcmN2LmNvbYIRKi5iai5iYWlkdWJjZS5jb22CDSouY2h1YW5rZS5jb22CESouY2xvdWQuYmFpZHUuY29tggsqLmRsbmVsLmNvbYILKi5kbG5lbC5vcmeCEiouZHVlcm9zLmJhaWR1LmNvbYIQKi5leXVuLmJhaWR1LmNvbYIRKi5mYW55aS5iYWlkdS5jb22CESouZ3ouYmFpZHViY2UuY29tghIqLmhhbzEyMy5iYWlkdS5jb22CDCouaGFvMTIzLmNvbYIMKi5oYW8yMjIuY29tggwqLmhhb2thbi5jb22CDiouaW0uYmFpZHUuY29tgg8qLm1hcC5iYWlkdS5jb22CDyoubWJkLmJhaWR1LmNvbYIMKi5taXBjZG4uY29tghAqLm5ld3MuYmFpZHUuY29tggsqLm51b21pLmNvbYIPKi5wYWUuYmFpZHUuY29tghAqLnNhZmUuYmFpZHUuY29tgg4qLnNtYXJ0YXBwcy5jboIOKi5zdS5iYWlkdS5jb22CDSoudHJ1c3Rnby5jb22CESoudmQuYmRzdGF0aWMuY29tghIqLnh1ZXNodS5iYWlkdS5jb22CC2Fwb2xsby5hdXRvggxiYWlmdWJhby5jb22CBmR3ei5jboIPbWN0LnkubnVvbWkuY29tggx3d3cuYmFpZHUuY26CEHd3dy5iYWlkdS5jb20uY24wHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFFh7jnUq/mGAqpBAAa7W6AdGbj9IMB0GA1UdDgQWBBSdx0oZ6fFp4D5huJntcykv7S7DmjATBgorBgEEAdZ5AgQDAQH/BAIFADAKBggqhkjOPQQDAwNoADBlAjEAs3tcpQdMNUFNoo38JCRCw0bZOs2nfV9GQ5ouCzUSvQKh6XIXp+hVrg1kBZVrTVS4AjAjcstk17oUmnNKG8+9VN2r4+3yb9oDeqJLOAjQJWcT0Ne7X1mcBmmba6PLKrIQOfI=\n-----END CERTIFICATE-----;"

// mutex for concurrent writes to cache
var mu sync.Mutex

func getSubjectPublicKeyInfoHash(subjectPublicKeyInfo []byte) string {
	h := sha256.New()
	h.Write(subjectPublicKeyInfo)
	hash := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(hash)

}

// TODO: fill fields of certificateCacheEntryConstructor calls

// function to parse PEM encoded certificates
func parsePEMCertificates(pemCertificatesString string, hashesString string, parentHashesString string) any {

	// get JavaScript constructor
	certificateCacheEntryGoConstructor := js.Global().Get("CertificateCacheEntryGo")

	hashToParsedCertificatesMap := make(map[string]interface{})
	// split the string containing hashes into a list of strings containing a single hash
	var hashes = strings.Split(hashesString, "\n")
	// split the string containing parentHashes into a list of strings containing a single parentHash
	var parentHashes = strings.Split(parentHashesString, "\n")

	// split the string containing all certificates into
	// a list of strings containing a single certificate
	var certificates = strings.Split(pemCertificatesString, ";")
	n_certificates := len(certificates) - 1
	//fmt.Println(n_certificates)
	//fmt.Println(hashes[0])
	//fmt.Println(parentHashes[0])

	// parse each single certificate using Goroutines for parallelism
	var wg sync.WaitGroup
	wg.Add(n_certificates)
	for i := 0; i < n_certificates; i++ {
		ci := i
		go func() {
			block, _ := pem.Decode([]byte(certificates[ci]))
			if block == nil {
				panic("failed to parse certificate PEM")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				panic("failed to parse certificate: " + err.Error())
			}

			var certificate js.Value
			if parentHashes[ci] == "null" {
				certificate = certificateCacheEntryGoConstructor.New(
					cert.Subject.String(),
					cert.Issuer.String(),
					time.Now().UTC().UnixMilli(), // TODO: maybe need to adjust
					base64.StdEncoding.EncodeToString(cert.RawTBSCertificate), // TODO: or just cert.Raw
					nil,
					cert.NotBefore.UnixMilli(),
					cert.NotAfter.UnixMilli(),
					getSubjectPublicKeyInfoHash(cert.RawSubjectPublicKeyInfo),
					nil,
					nil,
				)
			} else {
				certificate = certificateCacheEntryGoConstructor.New(
					cert.Subject.String(),
					cert.Issuer.String(),
					time.Now().UTC().UnixMilli(), // TODO: maybe need to adjust
					base64.StdEncoding.EncodeToString(cert.RawTBSCertificate), // TODO: or just cert.Raw
					parentHashes[ci],
					cert.NotBefore.UnixMilli(),
					cert.NotAfter.UnixMilli(),
					getSubjectPublicKeyInfoHash(cert.RawSubjectPublicKeyInfo),
					nil,
					nil,
				)
			}
			// create JavaScript type

			// append certificate to list
			mu.Lock()
			hashToParsedCertificatesMap[hashes[ci]] = certificate
			mu.Unlock()
			wg.Done()
		}()
	}
	wg.Wait()

	return hashToParsedCertificatesMap
}

func parsePEMCertificatesWrapper() js.Func {
	jsf := js.FuncOf(func(this js.Value, args []js.Value) any {

		// call function
		return parsePEMCertificates(args[0].String(), args[1].String(), args[2].String())

	})
	return jsf
}

func main() {

	js.Global().Set("parsePEMCertificates", parsePEMCertificatesWrapper())
	//js.Global().Set("parsePEMCertificateIterate", parsePEMCertificateIterateWrapper())

	// prevent program from terminating
	<-make(chan bool)

}
