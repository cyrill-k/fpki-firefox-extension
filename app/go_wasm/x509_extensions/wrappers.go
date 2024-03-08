package x509

// This file is a wrapper to export some unexported functions of the x509 library

const (
	LeafCertificate = iota
	IntermediateCertificate
	RootCertificate
)

func (c *Certificate) IsValid(certType int, currentChain []*Certificate, opts *VerifyOptions) error {

	return c.isValid(certType, currentChain, opts)

}

func CheckChainForKeyUsage(chain []*Certificate, keyUsages []ExtKeyUsage) bool {

	return checkChainForKeyUsage(chain, keyUsages)

}
