package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

type pinTestCertificate struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
}

func newPinTestCertificate(t *testing.T, name string, isCA bool, parent *pinTestCertificate) *pinTestCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	} else {
		template.DNSNames = []string{name}
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.certificate, parent.key
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(raw)
	require.NoError(t, err)
	return &pinTestCertificate{certificate: certificate, key: key}
}

func (c *pinTestCertificate) hash() option.CertificateHash {
	hash := sha256.Sum256(c.certificate.Raw)
	return hash[:]
}

func pinTestRoots(certificates ...*pinTestCertificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate.certificate)
	}
	return pool
}

// pinTestHandshake runs a client handshake with config against a server presenting chain.
func pinTestHandshake(t *testing.T, config Config, chain ...*pinTestCertificate) error {
	t.Helper()
	serverCertificate := tls.Certificate{PrivateKey: chain[0].key}
	for _, certificate := range chain {
		serverCertificate.Certificate = append(serverCertificate.Certificate, certificate.certificate.Raw)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		server, err := listener.Accept()
		if err != nil {
			return
		}
		serverConn := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{serverCertificate}})
		serverConn.Handshake()
		serverConn.Close()
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := ClientHandshake(ctx, client, config)
	if err == nil {
		conn.Close()
		return nil
	}
	require.NotErrorIs(t, err, context.DeadlineExceeded, "the handshake must fail on the certificate, not time out")
	return err
}

func newPinTestClient(t *testing.T, options option.OutboundTLSOptions) Config {
	t.Helper()
	options.Enabled = true
	config, err := NewClientWithOptions(ClientOptions{
		Context:       context.Background(),
		Logger:        log.NewNOPFactory().Logger(),
		ServerAddress: "198.51.100.1",
		Options:       options,
	})
	require.NoError(t, err)
	return config
}

func TestCertificatePinLeafAcceptsWithoutCA(t *testing.T) {
	leaf := newPinTestCertificate(t, "self-signed.example", false, nil)
	other := newPinTestCertificate(t, "other.example", false, nil)
	pinned := newPinTestClient(t, option.OutboundTLSOptions{
		ServerName:        "sni.example",
		CertificateSHA256: badoption.Listable[option.CertificateHash]{other.hash(), leaf.hash()},
	})
	require.NoError(t, pinTestHandshake(t, pinned, leaf), "a pinned leaf needs neither a CA nor a matching name")
	wrong := newPinTestClient(t, option.OutboundTLSOptions{
		ServerName:        "self-signed.example",
		CertificateSHA256: badoption.Listable[option.CertificateHash]{other.hash()},
	})
	require.ErrorContains(t, pinTestHandshake(t, wrong, leaf), "does not match certificate_sha256")
	plain := newPinTestClient(t, option.OutboundTLSOptions{ServerName: "self-signed.example"})
	require.Error(t, pinTestHandshake(t, plain, leaf), "without a pin the self-signed leaf is refused")
}

func TestCertificatePinCAIsTheTrustRoot(t *testing.T) {
	ca := newPinTestCertificate(t, "Pin Test CA", true, nil)
	leaf := newPinTestCertificate(t, "server.example", false, ca)
	pinned := newPinTestClient(t, option.OutboundTLSOptions{
		ServerName:        "server.example",
		CertificateSHA256: badoption.Listable[option.CertificateHash]{ca.hash()},
	})
	require.NoError(t, pinTestHandshake(t, pinned, leaf, ca))
	wrongName := newPinTestClient(t, option.OutboundTLSOptions{
		ServerName:        "elsewhere.example",
		CertificateSHA256: badoption.Listable[option.CertificateHash]{ca.hash()},
	})
	require.ErrorContains(t, pinTestHandshake(t, wrongName, leaf, ca), "verify remote certificate for elsewhere.example", "a pinned CA still checks the server name")
	// A pinned certificate further up the chain must be a CA.
	notCA := newPinTestCertificate(t, "not-a-ca.example", false, nil)
	signedByNotCA := newPinTestCertificate(t, "server.example", false, notCA)
	pinnedNotCA := newPinTestClient(t, option.OutboundTLSOptions{
		ServerName:        "server.example",
		CertificateSHA256: badoption.Listable[option.CertificateHash]{notCA.hash()},
	})
	require.ErrorContains(t, pinTestHandshake(t, pinnedNotCA, signedByNotCA, notCA), "does not match certificate_sha256")
}

func TestCertificatePinMismatchFailsEvenWhenCAValid(t *testing.T) {
	ca := newPinTestCertificate(t, "Trusted CA", true, nil)
	leaf := newPinTestCertificate(t, "server.example", false, ca)
	other := newPinTestCertificate(t, "other.example", false, nil)
	pin, err := newCertificatePin(option.OutboundTLSOptions{
		CertificateSHA256: badoption.Listable[option.CertificateHash]{other.hash()},
	}, pinTestRoots(ca), nil)
	require.NoError(t, err)
	require.ErrorContains(t, pin.verify("server.example", [][]byte{leaf.certificate.Raw, ca.certificate.Raw}), "does not match certificate_sha256")
	unpinned, err := newCertificatePin(option.OutboundTLSOptions{VerifyCertificateByName: []string{"server.example"}}, pinTestRoots(ca), nil)
	require.NoError(t, err)
	require.NoError(t, unpinned.verify("ignored.example", [][]byte{leaf.certificate.Raw, ca.certificate.Raw}))
}

func TestCertificatePinInsecureDoesNotDisablePins(t *testing.T) {
	leaf := newPinTestCertificate(t, "self-signed.example", false, nil)
	other := newPinTestCertificate(t, "other.example", false, nil)
	wrong := newPinTestClient(t, option.OutboundTLSOptions{
		Insecure:          true,
		CertificateSHA256: badoption.Listable[option.CertificateHash]{other.hash()},
	})
	require.Error(t, pinTestHandshake(t, wrong, leaf))
	right := newPinTestClient(t, option.OutboundTLSOptions{
		Insecure:          true,
		CertificateSHA256: badoption.Listable[option.CertificateHash]{leaf.hash()},
	})
	require.NoError(t, pinTestHandshake(t, right, leaf))
}

func TestVerifyCertificateByNameReplacesServerName(t *testing.T) {
	ca := newPinTestCertificate(t, "Pin Test CA", true, nil)
	leaf := newPinTestCertificate(t, "real.example", false, ca)
	byName := newPinTestClient(t, option.OutboundTLSOptions{
		ServerName:              "front.example",
		CertificateSHA256:       badoption.Listable[option.CertificateHash]{ca.hash()},
		VerifyCertificateByName: []string{"unrelated.example", "real.example"},
	})
	require.NoError(t, pinTestHandshake(t, byName, leaf, ca), "any listed name may match; the server name is not checked")
	noMatch := newPinTestClient(t, option.OutboundTLSOptions{
		ServerName:              "real.example",
		CertificateSHA256:       badoption.Listable[option.CertificateHash]{ca.hash()},
		VerifyCertificateByName: []string{"unrelated.example"},
	})
	require.Error(t, pinTestHandshake(t, noMatch, leaf, ca), "the server name does not count once names are listed")
}

func TestCertificatePinDisableSNIUsesConfiguredName(t *testing.T) {
	ca := newPinTestCertificate(t, "Pin Test CA", true, nil)
	leaf := newPinTestCertificate(t, "server.example", false, ca)
	config := newPinTestClient(t, option.OutboundTLSOptions{
		ServerName:        "server.example",
		DisableSNI:        true,
		CertificateSHA256: badoption.Listable[option.CertificateHash]{ca.hash()},
	})
	require.NoError(t, pinTestHandshake(t, config, leaf, ca))
	cloned := config.Clone()
	cloned.SetServerName("elsewhere.example")
	require.Error(t, pinTestHandshake(t, cloned, leaf, ca), "the pinned CA check follows SetServerName")
}

func TestCertificateHashJSON(t *testing.T) {
	sum := sha256.Sum256([]byte("certificate"))
	hexValue := hex.EncodeToString(sum[:])
	colons := strings.ToUpper(strings.Join(splitEvery(hexValue, 2), ":"))
	for _, input := range []string{hexValue, strings.ToUpper(hexValue), colons} {
		var hash option.CertificateHash
		require.NoError(t, json.Unmarshal([]byte(`"`+input+`"`), &hash), input)
		require.Equal(t, sum[:], []byte(hash))
	}
	encoded, err := json.Marshal(option.CertificateHash(sum[:]))
	require.NoError(t, err)
	var decoded option.CertificateHash
	require.NoError(t, json.Unmarshal(encoded, &decoded), "base64 as written by MarshalJSON")
	require.Equal(t, sum[:], []byte(decoded))
	for _, input := range []string{hexValue[:62], hexValue + "00", "zz" + hexValue[2:], "AAAA"} {
		var hash option.CertificateHash
		require.Error(t, json.Unmarshal([]byte(`"`+input+`"`), &hash), input)
	}
}

func splitEvery(value string, size int) []string {
	var parts []string
	for len(value) > 0 {
		parts = append(parts, value[:size])
		value = value[size:]
	}
	return parts
}

func TestCertificatePinConflicts(t *testing.T) {
	hash := option.CertificateHash(make([]byte, 32))
	for _, options := range []option.OutboundTLSOptions{
		{Enabled: true, ServerName: "a.example", CertificateSHA256: []option.CertificateHash{hash}, CertificatePublicKeySHA256: [][]byte{make([]byte, 32)}},
		{Enabled: true, ServerName: "a.example", CertificateSHA256: []option.CertificateHash{hash}, CertificatePath: "/ca.pem"},
		{Enabled: true, ServerName: "a.example", CertificateSHA256: []option.CertificateHash{hash}, Engine: "apple"},
		{Enabled: true, ServerName: "a.example", CertificateSHA256: []option.CertificateHash{hash[:16]}},
	} {
		_, err := NewClientWithOptions(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger(), Options: options})
		require.Error(t, err)
	}
}
