package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

const (
	keyPrefix  = "sck_"
	hashPrefix = "sha256:"
)

// GenerateKey returns a new raw API key: "sck_" followed by 43 base62 characters (256 bits).
func GenerateKey() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	s := new(big.Int).SetBytes(b[:]).Text(62)
	for len(s) < 43 {
		s = "0" + s
	}
	return keyPrefix + s, nil
}

// HashKey returns the stored form of a raw key.
func HashKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hashPrefix + hex.EncodeToString(sum[:])
}

// httpError is an error that carries the HTTP status to respond with.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func errStatus(status int, msg string) error { return &httpError{status, msg} }

// authenticate resolves the request's bearer key and applies expiry, IP and rate limits.
func (s *Server) authenticate(r *http.Request) (*Key, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	raw = strings.TrimSpace(raw)
	if !ok || raw == "" {
		return nil, errStatus(http.StatusUnauthorized, "missing bearer API key")
	}
	want := []byte(HashKey(raw))
	var found *Key
	for _, k := range s.config().Keys {
		// Compare against every key so timing does not reveal which one matched.
		if subtle.ConstantTimeCompare([]byte(k.Hash), want) == 1 {
			found = k
		}
	}
	if found == nil || found.Disabled {
		return nil, errStatus(http.StatusUnauthorized, "invalid API key")
	}
	if found.Expires != nil && !s.now().Before(*found.Expires) {
		return nil, errStatus(http.StatusUnauthorized, "API key expired")
	}
	if len(found.prefixes) > 0 {
		ip, err := remoteIP(r)
		if err != nil || !ipAllowed(found.prefixes, ip) {
			return nil, errStatus(http.StatusForbidden, "source IP not allowed for this key")
		}
	}
	if lim := s.limiter(found); lim != nil && !lim.Allow() {
		return nil, errStatus(http.StatusTooManyRequests, "rate limit exceeded for this key")
	}
	return found, nil
}

func remoteIP(r *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}
	return a.Unmap(), nil
}

func ipAllowed(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

type limiterEntry struct {
	rule RateLimitRule
	lim  *rate.Limiter
}

// limiter returns the key's rate limiter, keeping its state across config reloads
// unless the rule changed.
func (s *Server) limiter(k *Key) *rate.Limiter {
	if k.RateLimit.PerMinute == 0 {
		return nil
	}
	s.limMu.Lock()
	defer s.limMu.Unlock()
	if e, ok := s.limiters[k.Name]; ok && e.rule == k.RateLimit {
		return e.lim
	}
	burst := k.RateLimit.Burst
	if burst == 0 {
		burst = min(k.RateLimit.PerMinute, 10)
	}
	lim := rate.NewLimiter(rate.Every(time.Minute/time.Duration(k.RateLimit.PerMinute)), burst)
	s.limiters[k.Name] = limiterEntry{k.RateLimit, lim}
	return lim
}

// ValidateRawKey checks the shape of a key typed in by a user.
func ValidateRawKey(raw string) error {
	if !strings.HasPrefix(raw, keyPrefix) || len(raw) < len(keyPrefix)+20 {
		return errors.New("API keys look like sck_<random>")
	}
	return nil
}
