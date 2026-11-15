package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func createTestCertificateDER(t *testing.T, commonName string) []byte {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	return der
}

func TestParseDERCertificatesSkipsUnparsableCertificate(t *testing.T) {
	t.Parallel()
	// A well-formed DER SEQUENCE that is not a certificate.
	invalidCertificate := []byte{0x30, 0x03, 0x02, 0x01, 0x00}
	var der []byte
	der = append(der, createTestCertificateDER(t, "first")...)
	der = append(der, invalidCertificate...)
	der = append(der, createTestCertificateDER(t, "second")...)

	_, err := x509.ParseCertificates(der)
	require.Error(t, err)

	certificates := parseDERCertificates(der)
	require.Len(t, certificates, 2)
	require.Equal(t, "first", certificates[0].Subject.CommonName)
	require.Equal(t, "second", certificates[1].Subject.CommonName)
}

func TestParseDERCertificatesKeepsCertificatesBeforeTruncatedTail(t *testing.T) {
	t.Parallel()
	der := append(createTestCertificateDER(t, "first"), 0x30, 0x10, 0x00)
	certificates := parseDERCertificates(der)
	require.Len(t, certificates, 1)
	require.Equal(t, "first", certificates[0].Subject.CommonName)
}
