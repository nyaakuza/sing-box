//go:build with_naive_outbound

package naive

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// Cronet runs its own certificate verification, so the outbound must refuse checks it would not apply.
func TestOutboundRefusesCertificateChecks(t *testing.T) {
	for _, tls := range []option.OutboundTLSOptions{
		{Enabled: true, ServerName: "a.example", CertificateSHA256: badoption.Listable[option.CertificateHash]{make([]byte, 32)}},
		{Enabled: true, ServerName: "a.example", VerifyCertificateByName: []string{"b.example"}},
	} {
		_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().NewLogger("naive"), "naive", option.NaiveOutboundOptions{
			ServerOptions:               option.ServerOptions{Server: "192.0.2.1", ServerPort: 443},
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &tls},
		})
		require.ErrorContains(t, err, "not supported on naive outbound")
	}
}
