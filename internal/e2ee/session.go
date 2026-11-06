// Package e2ee implements the end-to-end encryption session used by the chat
// client.
//
// The session uses a hybrid post-quantum key agreement: a classical X25519
// ECDH exchange combined with an ML-KEM-768 (FIPS 203) encapsulation, so the
// derived secret stays confidential even if one of the two primitives is
// broken. The combined secret is expanded with HKDF-SHA256 (RFC 5869) into two
// independent directional AEAD keys — one per direction — which avoids any
// key/nonce reuse between the two peers.
//
// The full handshake transcript — both peers' X25519 and ML-KEM public keys
// plus the KEM ciphertext — is bound into the KDF salt. Without this binding
// an active attacker could try to synchronize the two honest parties onto the
// same derived key while retaining knowledge of one leg of the exchange,
// which would defeat the SAS comparison. With the transcript bound in, any
// substitution of key material yields different keys on the two ends and the
// safety codes diverge.
//
// Messages are sealed with ChaCha20-Poly1305 using a monotonically increasing
// 64-bit counter as the nonce. A per-direction key plus a counter guarantees
// nonce uniqueness, and the receiver rejects any counter it has already seen
// (replay protection). A short authentication string (SAS) lets both users
// compare a value out of band to detect an active man-in-the-middle.
package e2ee

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	keyLen = chacha20poly1305.KeySize

	infoDataLowToHigh = "e2ee-chat/v1/data/low->high"
	infoDataHighToLow = "e2ee-chat/v1/data/high->low"
	infoSAS           = "e2ee-chat/v1/sas"

	// 15 digits (~50 bits): long enough that grinding is hopeless, short
	// enough that users compare the whole code instead of a prefix — a
	// prefix comparison of a 30-digit code would collapse the effective
	// security to the compared prefix.
	sasDigits = 15
	sasGroup  = 5
)

// aad is authenticated but not encrypted; it binds ciphertexts to this
// protocol version so that replay across protocol revisions fails closed.
var aad = []byte("e2ee-chat/v1")

// Errors returned by the session.
var (
	ErrNotReady  = errors.New("e2ee: session is not established")
	ErrState     = errors.New("e2ee: operation not valid in current state")
	ErrReplay    = errors.New("e2ee: replayed or out-of-order message rejected")
	ErrMalformed = errors.New("e2ee: malformed key material or nonce")
	ErrExhausted = errors.New("e2ee: nonce space exhausted")
)

// KeyPair is the public key material a peer publishes during signaling.
type KeyPair struct {
	X25519 string `json:"x25519"`
	KEM    string `json:"kem"`
}

// Payload is the plaintext carried inside an encrypted message.
type Payload struct {
	Nickname string `json:"nick"`
	Text     string `json:"text"`
}

type state int

const (
	stateNew state = iota
	stateKeysExchanged
	stateReady
)

// Session holds one side of an encrypted chat session. It is not safe for
// concurrent use; the caller must serialize access (the client does so through
// its command loop).
type Session struct {
	x25519Priv *ecdh.PrivateKey
	x25519Pub  []byte

	kemPriv *mlkem.DecapsulationKey768
	kemPub  []byte

	peerX25519 []byte
	peerKEM    []byte

	initiator bool
	st        state

	ikm  []byte
	salt []byte

	sendKey   []byte
	recvKey   []byte
	sendNonce uint64
	recvNonce uint64
	recvSet   bool
}

// NewSession generates a fresh ephemeral key pair. X25519 provides forward
// secrecy and ML-KEM-768 provides post-quantum resistance.
func NewSession() (*Session, error) {
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("e2ee: generate x25519 key: %w", err)
	}
	kemPriv, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("e2ee: generate ml-kem key: %w", err)
	}
	return &Session{
		x25519Priv: xPriv,
		x25519Pub:  xPriv.PublicKey().Bytes(),
		kemPriv:    kemPriv,
		kemPub:     kemPriv.EncapsulationKey().Bytes(),
	}, nil
}

// PublicKeys returns the hex-encoded public key material to advertise.
func (s *Session) PublicKeys() KeyPair {
	return KeyPair{
		X25519: hex.EncodeToString(s.x25519Pub),
		KEM:    hex.EncodeToString(s.kemPub),
	}
}

// ExchangePeerKeys records and validates the peer's advertised public keys and
// computes the classical portion of the shared secret. It must be called
// exactly once, before Initiate or Complete.
func (s *Session) ExchangePeerKeys(peer KeyPair) error {
	if s.st != stateNew {
		return ErrState
	}
	if s.x25519Priv == nil || s.kemPriv == nil {
		// The session was closed or is otherwise unusable.
		return ErrState
	}

	peerX, err := hex.DecodeString(peer.X25519)
	if err != nil || len(peerX) != 32 {
		return ErrMalformed
	}
	peerXPub, err := ecdh.X25519().NewPublicKey(peerX)
	if err != nil {
		return ErrMalformed
	}

	peerKEMBytes, err := hex.DecodeString(peer.KEM)
	if err != nil {
		return ErrMalformed
	}
	peerKEM, err := mlkem.NewEncapsulationKey768(peerKEMBytes)
	if err != nil {
		return ErrMalformed
	}

	xShared, err := s.x25519Priv.ECDH(peerXPub)
	if err != nil {
		// ecdh rejects the identity/low-order point.
		return ErrMalformed
	}

	s.peerX25519 = peerX
	s.peerKEM = peerKEM.Bytes()
	s.x25519Priv = nil

	// The peer whose X25519 public key sorts first drives the ML-KEM
	// encapsulation, giving both sides a deterministic role.
	s.initiator = bytes.Compare(s.x25519Pub, peerX) < 0

	// The transcript salt covers all four public keys so that no key
	// substitution can synchronize the two honest endpoints.
	s.salt = concat(concatSorted(s.x25519Pub, peerX), concatSorted(s.kemPub, s.peerKEM))
	s.ikm = xShared
	s.st = stateKeysExchanged
	return nil
}

// Initiator reports whether this side must drive the ML-KEM encapsulation.
func (s *Session) Initiator() bool { return s.initiator }

// Started reports whether this session's key material has already been used
// in an exchange. A started session can never be reused for another pairing:
// the caller must generate a fresh one instead.
func (s *Session) Started() bool { return s.st != stateNew }

// Initiate performs the ML-KEM encapsulation and derives the session keys. It
// returns the KEM ciphertext that must be relayed to the peer. Only the
// initiator calls this.
func (s *Session) Initiate() ([]byte, error) {
	if s.st != stateKeysExchanged || !s.initiator {
		return nil, ErrState
	}
	ek, err := mlkem.NewEncapsulationKey768(s.peerKEM)
	if err != nil {
		return nil, ErrMalformed
	}
	kemShared, ct := ek.Encapsulate()
	// The initiator's own decapsulation key is no longer needed.
	s.kemPriv = nil
	if err := s.derive(kemShared, ct); err != nil {
		wipe(kemShared)
		return nil, err
	}
	wipe(kemShared)
	return ct, nil
}

// Complete performs the ML-KEM decapsulation with the ciphertext received from
// the initiator and derives the session keys. Only the responder calls this.
func (s *Session) Complete(kemCiphertext []byte) error {
	if s.st != stateKeysExchanged || s.initiator {
		return ErrState
	}
	if len(kemCiphertext) != mlkem.CiphertextSize768 {
		return ErrMalformed
	}
	kemShared, err := s.kemPriv.Decapsulate(kemCiphertext)
	if err != nil {
		return ErrMalformed
	}
	s.kemPriv = nil
	err = s.derive(kemShared, kemCiphertext)
	wipe(kemShared)
	return err
}

// derive expands the hybrid secret into the directional keys and the SAS
// input. The KEM ciphertext is appended to the transcript salt so that both
// peers derive identical keys only if they saw the exact same handshake
// material — any tampering with the encapsulation desynchronizes the SAS.
func (s *Session) derive(kemShared, kemCiphertext []byte) error {
	ikm := make([]byte, 0, len(s.ikm)+len(kemShared))
	ikm = append(ikm, s.ikm...)
	ikm = append(ikm, kemShared...)
	wipe(s.ikm)
	s.ikm = ikm

	salt := make([]byte, 0, len(s.salt)+len(kemCiphertext))
	salt = append(salt, s.salt...)
	salt = append(salt, kemCiphertext...)
	wipe(s.salt)
	s.salt = salt

	kLow, err := hkdf.Key(sha256.New, s.ikm, s.salt, infoDataLowToHigh, keyLen)
	if err != nil {
		return err
	}
	kHigh, err := hkdf.Key(sha256.New, s.ikm, s.salt, infoDataHighToLow, keyLen)
	if err != nil {
		return err
	}
	if s.initiator {
		s.sendKey, s.recvKey = kLow, kHigh
	} else {
		s.sendKey, s.recvKey = kHigh, kLow
	}
	s.st = stateReady
	return nil
}

// SafetyCode returns the short authentication string both peers can compare out
// of band. A mismatch indicates an active man-in-the-middle.
func (s *Session) SafetyCode() (string, error) {
	if s.st != stateReady {
		return "", ErrNotReady
	}
	raw, err := hkdf.Key(sha256.New, s.ikm, s.salt, infoSAS, 16)
	if err != nil {
		return "", err
	}
	n := new(big.Int).SetBytes(raw)
	mod := new(big.Int).Exp(big.NewInt(10), big.NewInt(sasDigits), nil)
	n.Mod(n, mod)

	digits := n.String()
	if len(digits) < sasDigits {
		digits = fmt.Sprintf("%0*s", sasDigits, digits)
	}
	var groups []string
	for i := 0; i < sasDigits; i += sasGroup {
		groups = append(groups, digits[i:i+sasGroup])
	}
	return strings.Join(groups, " "), nil
}

// Encrypt seals payload with the sender's directional key and the next counter.
func (s *Session) Encrypt(p Payload) (nonce, ciphertext []byte, err error) {
	if s.st != stateReady {
		return nil, nil, ErrNotReady
	}
	if s.sendNonce == ^uint64(0) {
		return nil, nil, ErrExhausted
	}

	plaintext, err := json.Marshal(p)
	if err != nil {
		return nil, nil, err
	}
	defer wipe(plaintext)

	nonce = make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], s.sendNonce)

	aead, err := chacha20poly1305.New(s.sendKey)
	if err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, aad)
	s.sendNonce++
	return nonce, ciphertext, nil
}

// Decrypt opens a ciphertext and enforces monotonic counters to reject replays.
func (s *Session) Decrypt(nonce, ciphertext []byte) (Payload, error) {
	var p Payload
	if s.st != stateReady {
		return p, ErrNotReady
	}
	if len(nonce) != chacha20poly1305.NonceSize || nonce[0]|nonce[1]|nonce[2]|nonce[3] != 0 {
		return p, ErrMalformed
	}

	counter := binary.BigEndian.Uint64(nonce[4:])
	if s.recvSet && counter <= s.recvNonce {
		return p, ErrReplay
	}

	aead, err := chacha20poly1305.New(s.recvKey)
	if err != nil {
		return p, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return p, err
	}
	defer wipe(plaintext)
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return Payload{}, err
	}
	s.recvNonce = counter
	s.recvSet = true
	return p, nil
}

// Close wipes the derived secrets on a best-effort basis. Go does not expose a
// way to zero the internal big-integer state of the key objects, so dropping
// the references is the best available guarantee for those.
func (s *Session) Close() {
	wipe(s.sendKey)
	wipe(s.recvKey)
	wipe(s.ikm)
	wipe(s.salt)
	wipe(s.x25519Pub)
	wipe(s.peerX25519)
	wipe(s.kemPub)
	wipe(s.peerKEM)
	s.sendKey, s.recvKey, s.ikm, s.salt = nil, nil, nil, nil
	s.x25519Priv, s.kemPriv = nil, nil
	s.st = stateNew
}

func concatSorted(a, b []byte) []byte {
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	return concat(a, b)
}

func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
