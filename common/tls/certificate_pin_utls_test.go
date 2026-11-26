//go:build with_utls

package tls

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// uTLS builds its own handshake, so the pin must reach it as it reaches the standard client.
func TestCertificatePinUTLS(t *testing.T) {
	ca := newPinTestCertificate(t, "Pin Test CA", true, nil)
	leaf := newPinTestCertificate(t, "server.example", false, ca)
	selfSigned := newPinTestCertificate(t, "self-signed.example", false, nil)
	fingerprint := &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
	for _, test := range []struct {
		name    string
		options option.OutboundTLSOptions
		chain   []*pinTestCertificate
		ok      bool
	}{
		{"leaf", option.OutboundTLSOptions{ServerName: "any.example", CertificateSHA256: badoption.Listable[option.CertificateHash]{selfSigned.hash()}}, []*pinTestCertificate{selfSigned}, true},
		{"wrong leaf", option.OutboundTLSOptions{ServerName: "any.example", CertificateSHA256: badoption.Listable[option.CertificateHash]{leaf.hash()}}, []*pinTestCertificate{selfSigned}, false},
		{"ca", option.OutboundTLSOptions{ServerName: "server.example", CertificateSHA256: badoption.Listable[option.CertificateHash]{ca.hash()}}, []*pinTestCertificate{leaf, ca}, true},
		{"ca wrong name", option.OutboundTLSOptions{ServerName: "elsewhere.example", CertificateSHA256: badoption.Listable[option.CertificateHash]{ca.hash()}}, []*pinTestCertificate{leaf, ca}, false},
		{"ca by name", option.OutboundTLSOptions{ServerName: "elsewhere.example", CertificateSHA256: badoption.Listable[option.CertificateHash]{ca.hash()}, VerifyCertificateByName: []string{"server.example"}}, []*pinTestCertificate{leaf, ca}, true},
		{"insecure wrong pin", option.OutboundTLSOptions{Insecure: true, CertificateSHA256: badoption.Listable[option.CertificateHash]{ca.hash()}}, []*pinTestCertificate{selfSigned}, false},
	} {
		test.options.UTLS = fingerprint
		err := pinTestHandshake(t, newPinTestClient(t, test.options), test.chain...)
		if test.ok {
			require.NoError(t, err, test.name)
		} else {
			require.Error(t, err, test.name)
		}
	}
}

func TestCertificatePinRefusedInReality(t *testing.T) {
	_, err := NewClientWithOptions(ClientOptions{
		Context: t.Context(),
		Options: option.OutboundTLSOptions{
			Enabled:           true,
			ServerName:        "a.example",
			CertificateSHA256: badoption.Listable[option.CertificateHash]{make([]byte, 32)},
			UTLS:              &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
			Reality:           &option.OutboundRealityOptions{Enabled: true, PublicKey: "yAnz5TF-lXXJte14tji3zlMNq-hd2rYUIgJBgB3fBmk", ShortID: "ab"},
		},
	})
	require.ErrorContains(t, err, "unsupported in reality")
}
