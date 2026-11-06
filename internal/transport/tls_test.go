package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSelfSigned(t *testing.T) (certFile, keyFile, pin string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	pin, err = PinFromCertFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, pin
}

func TestServerConfigRequiresTLS13(t *testing.T) {
	certFile, keyFile, _ := writeSelfSigned(t)
	cfg, err := ServerTLSConfig(ServerOptions{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("min version = %x", cfg.MinVersion)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatal("client auth should be disabled without a client CA")
	}
}

func TestServerConfigMTLS(t *testing.T) {
	certFile, keyFile, _ := writeSelfSigned(t)
	cfg, err := ServerTLSConfig(ServerOptions{CertFile: certFile, KeyFile: keyFile, ClientCAFile: certFile})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("expected mutual TLS")
	}
}

func TestPinnedClientAcceptsMatchingServer(t *testing.T) {
	certFile, keyFile, pin := writeSelfSigned(t)
	serverCfg, err := ServerTLSConfig(ServerOptions{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.(*tls.Conn).Handshake()
	}()

	clientCfg, err := ClientTLSConfig(ClientOptions{ServerName: "localhost", PinSHA256: pin})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn := tls.Client(raw, clientCfg)
	if err := conn.Handshake(); err != nil {
		t.Fatalf("handshake with correct pin failed: %v", err)
	}
}

func TestPinnedClientRejectsWrongPin(t *testing.T) {
	certFile, keyFile, _ := writeSelfSigned(t)
	serverCfg, _ := ServerTLSConfig(ServerOptions{CertFile: certFile, KeyFile: keyFile})

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.(*tls.Conn).Handshake()
	}()

	wrongPin := "0000000000000000000000000000000000000000000000000000000000000000"
	clientCfg, err := ClientTLSConfig(ClientOptions{ServerName: "localhost", PinSHA256: wrongPin})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := net.Dial("tcp", ln.Addr().String())
	defer raw.Close()
	conn := tls.Client(raw, clientCfg)
	if err := conn.Handshake(); err == nil {
		t.Fatal("handshake with wrong pin should fail")
	}
}

func TestParsePinValidation(t *testing.T) {
	if _, err := ClientTLSConfig(ClientOptions{PinSHA256: "zz"}); err == nil {
		t.Fatal("expected error for non-hex pin")
	}
	if _, err := ClientTLSConfig(ClientOptions{PinSHA256: "aabb"}); err == nil {
		t.Fatal("expected error for short pin")
	}
	pin := make([]byte, 32)
	for i := range pin {
		pin[i] = byte(i)
	}
	hexPin := ""
	for _, b := range pin {
		hexPin += string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&0xf])
	}
	if _, err := ClientTLSConfig(ClientOptions{PinSHA256: hexPin}); err != nil {
		t.Fatalf("valid pin rejected: %v", err)
	}
}
