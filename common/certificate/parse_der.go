package certificate

import (
	"crypto/x509"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// parseDERCertificates parses concatenated DER certificates one at a time and skips the ones
// x509 rejects, so a single unparsable certificate does not discard the whole store.
func parseDERCertificates(der []byte) []*x509.Certificate {
	var certificates []*x509.Certificate
	input := cryptobyte.String(der)
	for !input.Empty() {
		var element cryptobyte.String
		if !input.ReadASN1Element(&element, asn1.SEQUENCE) {
			break
		}
		certificate, err := x509.ParseCertificate(element)
		if err != nil {
			continue
		}
		certificates = append(certificates, certificate)
	}
	return certificates
}
