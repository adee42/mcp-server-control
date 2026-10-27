// Package tlsutil creates self-signed certificates and computes the fingerprints
// that sc-mcp pins.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Fingerprint formats the SHA-256 of a DER certificate as "SHA256:AB:CD:...".
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return formatFingerprint(sum[:])
}

func formatFingerprint(sum []byte) string {
	h := strings.ToUpper(hex.EncodeToString(sum))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return "SHA256:" + strings.Join(parts, ":")
}

// NormalizeFingerprint accepts "SHA256:AB:CD..", "ab cd ..", or plain hex and returns
// the canonical Fingerprint form.
func NormalizeFingerprint(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) >= 7 && strings.EqualFold(s[:7], "sha256:") {
		s = s[7:]
	}
	s = strings.NewReplacer(":", "", " ", "", "-", "").Replace(s)
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		return "", errors.New("fingerprint must be 32 bytes of hex (as printed by `sc-server fingerprint`)")
	}
	return formatFingerprint(b), nil
}

// FileFingerprint returns the fingerprint of the first certificate in a PEM file.
func FileFingerprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("%s: no PEM certificate found", certPath)
	}
	return Fingerprint(block.Bytes), nil
}

// GenerateSelfSigned writes a new ECDSA P-256 certificate and key valid for ten years.
// hosts may hold DNS names and IP addresses for the subject alternative names.
func GenerateSelfSigned(certPath, keyPath string, hosts []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	cn := "server-control"
	if len(hosts) > 0 {
		cn = hosts[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"server-control"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// DefaultHosts returns the machine's hostname, localhost and its non-loopback IPs.
func DefaultHosts() []string {
	var hosts []string
	if h, err := os.Hostname(); err == nil && h != "" {
		hosts = append(hosts, h)
	}
	hosts = append(hosts, "localhost", "127.0.0.1", "::1")
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
			hosts = append(hosts, ipn.IP.String())
		}
	}
	return hosts
}
