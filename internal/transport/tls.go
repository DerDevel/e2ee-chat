// Package transport builds hardened TLS configurations for the gRPC client and
// server. TLS 1.3 is mandatory and the post-quantum hybrid key exchange
// X25519MLKEM768 is preferred. The client always verifies the server identity,
// either through the system roots, an explicit CA bundle, or a pinned
// certificate fingerprint for self-signed deployments.
package transport

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// minimum TLS version and the preferred (post-quantum) key exchanges.
const minVersion = tls.VersionTLS13

var curves = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}

// ClientOptions configures the client TLS stack.
type ClientOptions struct {
	// ServerName is the expected name in the server certificate.
	ServerName string
	// CAFile is an optional PEM bundle used as the trust anchor.
	CAFile string
	// PinSHA256 is an optional hex SHA-256 fingerprint of the server leaf
	// certificate (colons are ignored). When set without CAFile it becomes the
	// sole trust anchor, which is how self-signed servers are trusted safely.
	PinSHA256 string
	// Insecure disables verification entirely. Intended only for local
	// development; callers should warn loudly when setting it.
	Insecure bool
}

// ClientTLSConfig returns a TLS config that authenticates the server.
func ClientTLSConfig(o ClientOptions) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:       minVersion,
		ServerName:       o.ServerName,
		CurvePreferences: curves,
	}

	if o.CAFile != "" {
		pool, err := loadCertPool(o.CAFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}

	pin, err := parsePin(o.PinSHA256)
	if err != nil {
		return nil, err
	}

	// A pin without a CA is a self-contained trust anchor: standard chain
	// verification has no PKI to validate against, so the pin replaces it.
	if pin != nil && o.CAFile == "" {
		cfg.InsecureSkipVerify = true
	}
	if o.Insecure {
		cfg.InsecureSkipVerify = true
	}

	if pin != nil {
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("transport: peer presented no certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return errors.New("transport: server certificate pin mismatch")
			}
			return nil
		}
	}
	return cfg, nil
}

// ServerOptions configures the server TLS stack.
type ServerOptions struct {
	CertFile string
	KeyFile  string
	// ClientCAFile, when set, enables mutual TLS: every client must present a
	// certificate that chains to this CA.
	ClientCAFile string
}

// ServerTLSConfig returns a TLS config for the relay server.
func ServerTLSConfig(o ServerOptions) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("transport: load server key pair: %w", err)
	}

	cfg := &tls.Config{
		MinVersion:       minVersion,
		CurvePreferences: curves,
		Certificates:     []tls.Certificate{cert},
		ClientAuth:       tls.NoClientCert,
	}

	if o.ClientCAFile != "" {
		pool, err := loadCertPool(o.ClientCAFile)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// PinFromCertFile returns the hex SHA-256 fingerprint of the first certificate
// in a PEM file. It is used to generate a pin for self-signed servers.
func PinFromCertFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", errors.New("transport: no PEM block found")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

func parsePin(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	s = strings.ReplaceAll(s, ":", "")
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("transport: invalid certificate pin: %w", err)
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("transport: certificate pin must be %d bytes", sha256.Size)
	}
	return raw, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("transport: read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("transport: no certificates found in CA file")
	}
	return pool, nil
}
