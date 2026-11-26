package tls

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// certificatePin checks server certificates the way Xray-core's pinnedPeerCertSha256 and verifyPeerCertByName do
// (transport/internet/tls/config.go: verifyPeerCert and verifyChain):
//   - a hash matching the leaf certificate accepts it, with no CA or name check;
//   - otherwise a hash matching a CA certificate further up the presented chain makes it the only trust root;
//   - otherwise the handshake fails;
//   - names, when set, replace the server name in the hostname check: any one of them must verify.
type certificatePin struct {
	hashes [][]byte
	names  []string
	roots  *x509.CertPool
	now    func() time.Time
}

func newCertificatePin(options option.OutboundTLSOptions, roots *x509.CertPool, timeFunc func() time.Time) (*certificatePin, error) {
	var names []string
	for _, name := range options.VerifyCertificateByName {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	if len(options.CertificateSHA256) == 0 && len(names) == 0 {
		return nil, nil
	}
	if options.Reality != nil && options.Reality.Enabled {
		return nil, E.New("certificate_sha256 and verify_certificate_by_name are unsupported in reality")
	}
	if len(options.CertificatePublicKeySHA256) > 0 {
		return nil, E.New("certificate_sha256 and verify_certificate_by_name are conflict with certificate_public_key_sha256")
	}
	if len(options.CertificateSHA256) > 0 && (len(options.Certificate) > 0 || options.CertificatePath != "") {
		return nil, E.New("certificate_sha256 is conflict with certificate or certificate_path")
	}
	hashes := make([][]byte, 0, len(options.CertificateSHA256))
	for _, hash := range options.CertificateSHA256 {
		if len(hash) != sha256.Size {
			return nil, E.New("invalid certificate_sha256 length: ", len(hash))
		}
		hashes = append(hashes, []byte(hash))
	}
	if timeFunc == nil {
		timeFunc = time.Now
	}
	return &certificatePin{hashes: hashes, names: names, roots: roots, now: timeFunc}, nil
}

func (p *certificatePin) verifier(serverName string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		return p.verify(serverName, rawCerts)
	}
}

func (p *certificatePin) matches(rawCert []byte) bool {
	hash := sha256.Sum256(rawCert)
	matched := false
	for _, pinned := range p.hashes {
		if subtle.ConstantTimeCompare(hash[:], pinned) == 1 {
			matched = true
		}
	}
	return matched
}

func (p *certificatePin) verify(serverName string, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return E.New("missing remote certificate")
	}
	certificates := make([]*x509.Certificate, len(rawCerts))
	for i, rawCert := range rawCerts {
		certificate, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return E.Cause(err, "parse remote certificate")
		}
		certificates[i] = certificate
	}
	roots := p.roots
	if len(p.hashes) > 0 {
		if p.matches(rawCerts[0]) {
			return nil
		}
		var pinnedCA *x509.Certificate
		for _, certificate := range certificates[1:] {
			if certificate.IsCA && p.matches(certificate.Raw) {
				pinnedCA = certificate
				break
			}
		}
		if pinnedCA == nil {
			return E.New("remote certificate chain does not match certificate_sha256")
		}
		roots = x509.NewCertPool()
		roots.AddCert(pinnedCA)
	}
	names := p.names
	if len(names) == 0 {
		if serverName == "" {
			return E.New("a certificate_sha256 CA needs server_name")
		}
		names = []string{serverName}
	}
	options := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   p.now(),
	}
	for _, certificate := range certificates[1:] {
		options.Intermediates.AddCert(certificate)
	}
	var lastErr error
	for _, name := range names {
		options.DNSName = name
		if _, lastErr = certificates[0].Verify(options); lastErr == nil {
			return nil
		}
	}
	return E.Cause(lastErr, "verify remote certificate for ", strings.Join(names, ", "))
}
