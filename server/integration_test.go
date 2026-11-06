package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"e2ee-chat/internal/e2ee"
	"e2ee-chat/internal/transport"
	pb "e2ee-chat/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Integration test: the full protocol over real TLS and gRPC on the loopback
// interface — room registration, pairing, the hybrid key agreement relayed
// through the server, and encrypted chat in both directions.

func writeCertPair(t *testing.T) (certFile, keyFile, pin string) {
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
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	pin, err = transport.PinFromCertFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, pin
}

type testClient struct {
	stream  pb.ChatService_ConnectClient
	session *e2ee.Session
}

// next waits for a server message of the wanted kind ("incoming",
// "established", "kem", "chat" or "any"), failing on transport errors.
func next(t *testing.T, c *testClient, want string) *pb.ServerMessage {
	t.Helper()
	for {
		msg, err := c.stream.Recv()
		if err != nil {
			t.Fatalf("recv while waiting for %s: %v", want, err)
		}
		if want == "any" {
			return msg
		}
		var kind string
		switch msg.Payload.(type) {
		case *pb.ServerMessage_Error:
			kind = "error"
		case *pb.ServerMessage_IncomingRequest:
			kind = "incoming"
		case *pb.ServerMessage_ConnectionEstablished:
			kind = "established"
		case *pb.ServerMessage_KemCiphertext:
			kind = "kem"
		case *pb.ServerMessage_ChatMessage:
			kind = "chat"
		}
		if kind == want {
			return msg
		}
		t.Fatalf("got %s while waiting for %s: %v", kind, want, msg)
	}
}

func TestEndToEndSessionOverTLS(t *testing.T) {
	certFile, keyFile, pin := writeCertPair(t)
	srvCfg, err := transport.ServerTLSConfig(transport.ServerOptions{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}

	store := newFakeStore()
	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(srvCfg)),
		grpc.MaxRecvMsgSize(maxMessageSize),
		grpc.MaxSendMsgSize(maxMessageSize),
	)
	pb.RegisterChatServiceServer(grpcServer, &server{
		relay: newRelay(store),
		sem:   make(chan struct{}, maxConcurrentSessions),
		ips:   newIPGauge(),
	})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	go func() { _ = grpcServer.Serve(lis) }()
	defer grpcServer.Stop()

	clientCfg, err := transport.ClientTLSConfig(transport.ClientOptions{
		ServerName: "localhost",
		PinSHA256:  pin,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dial := func() (*testClient, func()) {
		t.Helper()
		conn, err := grpc.NewClient(lis.Addr().String(),
			grpc.WithTransportCredentials(credentials.NewTLS(clientCfg)),
		)
		if err != nil {
			t.Fatal(err)
		}
		stream, err := pb.NewChatServiceClient(conn).Connect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		s, err := e2ee.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		return &testClient{stream: stream, session: s}, func() { _ = conn.Close() }
	}

	alice, closeAlice := dial()
	defer closeAlice()
	bob, closeBob := dial()
	defer closeBob()

	ak := alice.session.PublicKeys()
	bk := bob.session.PublicKeys()

	// 1. Alice registers the room. Registration has no ack, so wait until the
	// room is visible in the store before Bob looks for it — the two streams
	// are separate connections and their relative ordering is not guaranteed.
	if err := alice.stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_RegisterRoom{
		RegisterRoom: &pb.RegisterRoomRequest{Keyword: "it-room", PublicKey: ak.X25519, KemPublicKey: ak.KEM},
	}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		ctxGet, cancelGet := context.WithTimeout(context.Background(), time.Second)
		_, err := store.Get(ctxGet, roomKey("it-room"))
		cancelGet()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("room never appeared in the store")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 2. Bob finds it.
	if err := bob.stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_FindRoom{
		FindRoom: &pb.FindRoomRequest{Keyword: "it-room", PublicKey: bk.X25519, KemPublicKey: bk.KEM},
	}}); err != nil {
		t.Fatal(err)
	}
	next(t, alice, "incoming")

	// 3. Alice accepts.
	if err := alice.stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_AcceptConnection{
		AcceptConnection: &pb.AcceptConnectionRequest{Accepted: true},
	}}); err != nil {
		t.Fatal(err)
	}
	estA := next(t, alice, "established").GetConnectionEstablished()
	estB := next(t, bob, "established").GetConnectionEstablished()

	if estA.PeerPublicKey != bk.X25519 || estB.PeerPublicKey != ak.X25519 {
		t.Fatal("peers received wrong keys")
	}

	// 4. Hybrid key agreement.
	if err := alice.session.ExchangePeerKeys(e2ee.KeyPair{X25519: estA.PeerPublicKey, KEM: estA.PeerKemPublicKey}); err != nil {
		t.Fatal(err)
	}
	if err := bob.session.ExchangePeerKeys(e2ee.KeyPair{X25519: estB.PeerPublicKey, KEM: estB.PeerKemPublicKey}); err != nil {
		t.Fatal(err)
	}

	init, resp := alice, bob
	if !alice.session.Initiator() {
		init, resp = bob, alice
	}
	ct, err := init.session.Initiate()
	if err != nil {
		t.Fatal(err)
	}
	if err := init.stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_KemCiphertext{
		KemCiphertext: &pb.KemCiphertext{Ciphertext: ct},
	}}); err != nil {
		t.Fatal(err)
	}
	kemMsg := next(t, resp, "kem").GetKemCiphertext()
	if err := resp.session.Complete(kemMsg.Ciphertext); err != nil {
		t.Fatal(err)
	}

	// 5. Both sides must agree on the safety code.
	sa, err := alice.session.SafetyCode()
	if err != nil {
		t.Fatal(err)
	}
	sb, err := bob.session.SafetyCode()
	if err != nil {
		t.Fatal(err)
	}
	if sa != sb {
		t.Fatalf("safety codes differ over the wire: %q vs %q", sa, sb)
	}

	// 6. Encrypted chat in both directions, UTF-8 included.
	send := func(c *testClient, text string) {
		t.Helper()
		n, ct, err := c.session.Encrypt(e2ee.Payload{Nickname: "tester", Text: text})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_ChatMessage{
			ChatMessage: &pb.EncryptedPayload{Nonce: n, Ciphertext: ct},
		}}); err != nil {
			t.Fatal(err)
		}
	}

	send(alice, "привет, Боб 👋")
	got := next(t, bob, "chat").GetChatMessage()
	p, err := bob.session.Decrypt(got.Nonce, got.Ciphertext)
	if err != nil {
		t.Fatalf("bob decrypt: %v", err)
	}
	if p.Text != "привет, Боб 👋" {
		t.Fatalf("utf-8 roundtrip broken: %q", p.Text)
	}

	send(bob, "и тебе привет")
	got = next(t, alice, "chat").GetChatMessage()
	p, err = alice.session.Decrypt(got.Nonce, got.Ciphertext)
	if err != nil {
		t.Fatalf("alice decrypt: %v", err)
	}
	if p.Text != "и тебе привет" {
		t.Fatalf("unexpected plaintext: %q", p.Text)
	}

	// 7. A malformed KEM ciphertext must be rejected by the server, not relayed.
	if err := alice.stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_KemCiphertext{
		KemCiphertext: &pb.KemCiphertext{Ciphertext: make([]byte, 10)},
	}}); err != nil {
		t.Fatal(err)
	}
	if e := next(t, alice, "any").GetError(); e == nil {
		t.Fatal("short KEM ciphertext must be rejected")
	}
}
