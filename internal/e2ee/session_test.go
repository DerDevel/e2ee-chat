package e2ee

import (
	"bytes"
	"crypto/mlkem"
	"errors"
	"testing"
)

// pair establishes two fully keyed sessions and returns them.
func pair(t *testing.T) (*Session, *Session) {
	t.Helper()
	a, err := NewSession()
	if err != nil {
		t.Fatalf("new session a: %v", err)
	}
	b, err := NewSession()
	if err != nil {
		t.Fatalf("new session b: %v", err)
	}
	if err := a.ExchangePeerKeys(b.PublicKeys()); err != nil {
		t.Fatalf("a exchange: %v", err)
	}
	if err := b.ExchangePeerKeys(a.PublicKeys()); err != nil {
		t.Fatalf("b exchange: %v", err)
	}

	init, resp := a, b
	if !a.Initiator() {
		init, resp = b, a
	}
	ct, err := init.Initiate()
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	if err := resp.Complete(ct); err != nil {
		t.Fatalf("complete: %v", err)
	}
	return a, b
}

func TestRoundTripBothDirections(t *testing.T) {
	a, b := pair(t)

	n, ct, err := a.Encrypt(Payload{Nickname: "alice", Text: "hello bob"})
	if err != nil {
		t.Fatalf("a encrypt: %v", err)
	}
	got, err := b.Decrypt(n, ct)
	if err != nil {
		t.Fatalf("b decrypt: %v", err)
	}
	if got.Nickname != "alice" || got.Text != "hello bob" {
		t.Fatalf("got %+v", got)
	}

	n, ct, err = b.Encrypt(Payload{Nickname: "bob", Text: "hi alice"})
	if err != nil {
		t.Fatalf("b encrypt: %v", err)
	}
	got, err = a.Decrypt(n, ct)
	if err != nil {
		t.Fatalf("a decrypt: %v", err)
	}
	if got.Nickname != "bob" || got.Text != "hi alice" {
		t.Fatalf("got %+v", got)
	}
}

func TestDirectionalKeysDifferButMatch(t *testing.T) {
	a, b := pair(t)
	if bytes.Equal(a.sendKey, a.recvKey) {
		t.Fatal("directional keys must differ")
	}
	if !bytes.Equal(a.sendKey, b.recvKey) || !bytes.Equal(a.recvKey, b.sendKey) {
		t.Fatal("send/recv keys must be mirrored between peers")
	}
}

func TestSafetyCodeMatches(t *testing.T) {
	a, b := pair(t)
	ca, err := a.SafetyCode()
	if err != nil {
		t.Fatalf("a sas: %v", err)
	}
	cb, err := b.SafetyCode()
	if err != nil {
		t.Fatalf("b sas: %v", err)
	}
	if ca != cb {
		t.Fatalf("safety codes differ: %q != %q", ca, cb)
	}
	if len(ca) != sasDigits+sasDigits/sasGroup-1 {
		t.Fatalf("unexpected safety code format: %q", ca)
	}
}

func TestTamperedCiphertextRejected(t *testing.T) {
	a, b := pair(t)
	n, ct, _ := a.Encrypt(Payload{Nickname: "a", Text: "x"})
	ct[len(ct)-1] ^= 0x01
	if _, err := b.Decrypt(n, ct); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestReplayRejected(t *testing.T) {
	a, b := pair(t)
	n, ct, _ := a.Encrypt(Payload{Nickname: "a", Text: "x"})
	if _, err := b.Decrypt(n, ct); err != nil {
		t.Fatalf("first decrypt: %v", err)
	}
	if _, err := b.Decrypt(n, ct); !errors.Is(err, ErrReplay) {
		t.Fatalf("want ErrReplay, got %v", err)
	}
}

func TestFirstMessageCounterZeroAccepted(t *testing.T) {
	a, b := pair(t)
	_, _, _ = a.Encrypt(Payload{Nickname: "a", Text: "first"})
	n, ct, _ := a.Encrypt(Payload{Nickname: "a", Text: "second"})
	if n[11] != 1 {
		t.Fatalf("expected counter 1, nonce=%x", n)
	}
	if _, err := b.Decrypt(n, ct); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
}

func TestMalformedPeerKeyRejected(t *testing.T) {
	a, _ := NewSession()
	cases := []KeyPair{
		{X25519: "zz", KEM: "zz"},
		{X25519: string(make([]byte, 64)), KEM: "00"},
	}
	for _, c := range cases {
		s, _ := NewSession()
		if err := s.ExchangePeerKeys(c); !errors.Is(err, ErrMalformed) {
			t.Fatalf("want ErrMalformed for %+v, got %v", c, err)
		}
	}
	_ = a
}

func TestLowOrderPeerKeyRejected(t *testing.T) {
	s, _ := NewSession()
	zeroX := "0000000000000000000000000000000000000000000000000000000000000000"
	// A valid-length KEM key is needed to reach the ECDH step.
	other, _ := NewSession()
	if err := s.ExchangePeerKeys(KeyPair{X25519: zeroX, KEM: other.PublicKeys().KEM}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed for low-order key, got %v", err)
	}
}

func TestWrongKEMCiphertextBreaksDecryption(t *testing.T) {
	a, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewSession()
	if err := a.ExchangePeerKeys(b.PublicKeys()); err != nil {
		t.Fatal(err)
	}
	if err := b.ExchangePeerKeys(a.PublicKeys()); err != nil {
		t.Fatal(err)
	}
	init, resp := a, b
	if !a.Initiator() {
		init, resp = b, a
	}
	if _, err := init.Initiate(); err != nil {
		t.Fatal(err)
	}
	// Implicit rejection: a corrupted ciphertext decapsulates to a different
	// secret without an error, so the peers must end up with mismatched keys.
	bogus := make([]byte, 1088) // ML-KEM-768 ciphertext length
	if err := resp.Complete(bogus); err != nil {
		t.Fatalf("complete: %v", err)
	}
	n, ct, _ := init.Encrypt(Payload{Text: "x"})
	if _, err := resp.Decrypt(n, ct); err == nil {
		t.Fatal("mismatched keys should not decrypt")
	}
}

func TestBadNonceRejected(t *testing.T) {
	a, b := pair(t)
	_, ct, _ := a.Encrypt(Payload{Text: "x"})
	if _, err := b.Decrypt([]byte{1, 2, 3}, ct); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
	bad := make([]byte, 12)
	bad[0] = 1
	if _, err := b.Decrypt(bad, ct); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed for non-zero prefix, got %v", err)
	}
}

func TestOperationsRequireEstablishedState(t *testing.T) {
	s, _ := NewSession()
	if _, _, err := s.Encrypt(Payload{}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("want ErrNotReady, got %v", err)
	}
	if _, err := s.SafetyCode(); !errors.Is(err, ErrNotReady) {
		t.Fatalf("want ErrNotReady, got %v", err)
	}
	if err := s.Complete([]byte("x")); !errors.Is(err, ErrState) {
		t.Fatalf("want ErrState, got %v", err)
	}
}

// A man in the middle who substitutes their own KEM public key must not be
// able to synchronize the two honest endpoints onto the same derived keys:
// with the transcript bound into the KDF the safety codes diverge.
func TestSubstitutedKEMKeyDesynchronizesSAS(t *testing.T) {
	a, _ := NewSession()
	b, _ := NewSession()
	mitm, _ := NewSession()

	// MITM hands each side their own KEM key but keeps X25519 keys intact —
	// the strongest substitution available to them.
	if err := a.ExchangePeerKeys(KeyPair{X25519: b.PublicKeys().X25519, KEM: mitm.PublicKeys().KEM}); err != nil {
		t.Fatal(err)
	}
	if err := b.ExchangePeerKeys(KeyPair{X25519: a.PublicKeys().X25519, KEM: mitm.PublicKeys().KEM}); err != nil {
		t.Fatal(err)
	}

	init, resp := a, b
	if !a.Initiator() {
		init, resp = b, a
	}
	ct, err := init.Initiate()
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Complete(ct); err != nil {
		t.Fatal(err)
	}

	ca, _ := a.SafetyCode()
	cb, _ := b.SafetyCode()
	if ca == cb {
		t.Fatal("KEM key substitution must desynchronize the safety codes")
	}
}

// Swapping the KEM ciphertext for one encapsulated against a different key
// must break decryption rather than silently re-synchronizing the peers.
func TestTransplantedCiphertextDesynchronizes(t *testing.T) {
	a, _ := NewSession()
	b, _ := NewSession()
	init, resp := a, b
	if err := a.ExchangePeerKeys(b.PublicKeys()); err != nil {
		t.Fatal(err)
	}
	if err := b.ExchangePeerKeys(a.PublicKeys()); err != nil {
		t.Fatal(err)
	}
	if !a.Initiator() {
		init, resp = b, a
	}
	if _, err := init.Initiate(); err != nil {
		t.Fatal(err)
	}

	// A second, independent ciphertext encapsulated to some other key.
	other, _ := NewSession()
	ek, err := mlkem.NewEncapsulationKey768(other.kemPub)
	if err != nil {
		t.Fatal(err)
	}
	_, foreignCt := ek.Encapsulate()

	if err := resp.Complete(foreignCt); err != nil {
		t.Fatal(err)
	}
	n, ct, _ := init.Encrypt(Payload{Text: "x"})
	if _, err := resp.Decrypt(n, ct); err == nil {
		t.Fatal("transplanted ciphertext must not yield working keys")
	}
}

func TestClosedSessionIsUnusable(t *testing.T) {
	a, b := pair(t)
	a.Close()
	b.Close()

	// Must fail cleanly instead of panicking on wiped key material.
	c, _ := NewSession()
	if err := a.ExchangePeerKeys(c.PublicKeys()); !errors.Is(err, ErrState) {
		t.Fatalf("want ErrState, got %v", err)
	}
	if _, _, err := a.Encrypt(Payload{}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("want ErrNotReady, got %v", err)
	}
}

func TestSessionCannotExchangeTwice(t *testing.T) {
	a, _ := NewSession()
	b, _ := NewSession()
	if err := a.ExchangePeerKeys(b.PublicKeys()); err != nil {
		t.Fatal(err)
	}
	if a.Started() != true {
		t.Fatal("session must report started after exchange")
	}
	if err := a.ExchangePeerKeys(b.PublicKeys()); !errors.Is(err, ErrState) {
		t.Fatalf("want ErrState on second exchange, got %v", err)
	}
}

func TestWrongLengthKEMCiphertextRejected(t *testing.T) {
	a, _ := NewSession()
	b, _ := NewSession()
	if err := a.ExchangePeerKeys(b.PublicKeys()); err != nil {
		t.Fatal(err)
	}
	if err := b.ExchangePeerKeys(a.PublicKeys()); err != nil {
		t.Fatal(err)
	}
	resp := b
	if b.Initiator() {
		resp = a
	}
	if err := resp.Complete(make([]byte, 1087)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}
