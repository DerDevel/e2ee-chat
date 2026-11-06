package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pb "e2ee-chat/proto"

	"golang.org/x/time/rate"
)

type fakeStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newFakeStore() *fakeStore { return &fakeStore{m: make(map[string][]byte)} }

func (f *fakeStore) SetNX(_ context.Context, key string, value []byte, _ time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.m[key]; ok {
		return false, nil
	}
	f.m[key] = append([]byte(nil), value...)
	return true, nil
}

func (f *fakeStore) Get(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), v...), nil
}

func (f *fakeStore) Del(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, key)
	return nil
}

func (f *fakeStore) CompareDelete(_ context.Context, key string, ownerPrefix string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.m[key]; ok && bytes.HasPrefix(v, []byte(ownerPrefix)) {
		delete(f.m, key)
	}
	return nil
}

type fakePeer struct {
	mu   sync.Mutex
	msgs []*pb.ServerMessage
}

func (p *fakePeer) Send(m *pb.ServerMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.msgs = append(p.msgs, m)
	return nil
}

func (p *fakePeer) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.msgs)
}

func (p *fakePeer) last() *pb.ServerMessage {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.msgs) == 0 {
		return nil
	}
	return p.msgs[len(p.msgs)-1]
}

func validKeys(seed string) (string, string) {
	x := strings.Repeat(seed, 64)
	kem := strings.Repeat(seed, 2368)
	if len(x) > 64 {
		x = x[:64]
	}
	if len(kem) > 2368 {
		kem = kem[:2368]
	}
	return x, kem
}

func attach(t *testing.T, r *relay, id string) *fakePeer {
	t.Helper()
	p := &fakePeer{}
	r.Attach(id, p, rate.NewLimiter(rate.Inf, 0), rate.NewLimiter(rate.Inf, 0))
	return p
}

func TestRegisterRejectsDuplicateRoom(t *testing.T) {
	r := newRelay(newFakeStore())
	attach(t, r, "a")
	attach(t, r, "b")
	x, kem := validKeys("a")

	if err := r.Register("a", "room1", x, kem); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := r.Register("b", "room1", x, kem); err == nil {
		t.Fatal("duplicate room must be rejected")
	}
}

func TestFindAcceptEstablishesPair(t *testing.T) {
	store := newFakeStore()
	r := newRelay(store)
	owner := attach(t, r, "owner")
	joiner := attach(t, r, "joiner")
	ox, okem := validKeys("a")
	jx, jkem := validKeys("b")

	if err := r.Register("owner", "room1", ox, okem); err != nil {
		t.Fatal(err)
	}
	if err := r.Find("joiner", "room1", jx, jkem); err != nil {
		t.Fatal(err)
	}

	req, ok := owner.last().Payload.(*pb.ServerMessage_IncomingRequest)
	if !ok {
		t.Fatalf("owner did not receive incoming request: %v", owner.last())
	}
	if req.IncomingRequest.PeerPublicKey != jx || req.IncomingRequest.PeerKemPublicKey != jkem {
		t.Fatal("incoming request carried wrong joiner keys")
	}

	if err := r.Accept("owner", true); err != nil {
		t.Fatal(err)
	}

	oe, ok := owner.last().Payload.(*pb.ServerMessage_ConnectionEstablished)
	if !ok {
		t.Fatal("owner did not receive established")
	}
	if oe.ConnectionEstablished.PeerPublicKey != jx || oe.ConnectionEstablished.PeerKemPublicKey != jkem {
		t.Fatal("owner got wrong peer keys")
	}

	je, ok := joiner.last().Payload.(*pb.ServerMessage_ConnectionEstablished)
	if !ok {
		t.Fatal("joiner did not receive established")
	}
	if je.ConnectionEstablished.PeerPublicKey != ox || je.ConnectionEstablished.PeerKemPublicKey != okem {
		t.Fatal("joiner got wrong peer keys")
	}

	// Room must be released after pairing.
	if _, err := store.Get(context.Background(), roomKey("room1")); err == nil {
		t.Fatal("room key must be deleted after pairing")
	}
	// And the keyword becomes claimable again once the pair dissolves.
	r.Detach("owner")
	r.Detach("joiner")
	if err := r.Register("owner", "room1", ox, okem); err != nil {
		t.Fatalf("room should be claimable after the pair dissolved: %v", err)
	}
}

func TestOnlyOwnerMayAccept(t *testing.T) {
	r := newRelay(newFakeStore())
	attach(t, r, "owner")
	attach(t, r, "joiner")
	x, kem := validKeys("a")
	_ = r.Register("owner", "room1", x, kem)
	_ = r.Find("joiner", "room1", x, kem)

	if err := r.Accept("joiner", true); err == nil {
		t.Fatal("non-owner accept must be rejected")
	}
}

func TestRejectNotifiesJoiner(t *testing.T) {
	r := newRelay(newFakeStore())
	attach(t, r, "owner")
	joiner := attach(t, r, "joiner")
	x, kem := validKeys("a")
	_ = r.Register("owner", "room1", x, kem)
	_ = r.Find("joiner", "room1", x, kem)
	_ = r.Accept("owner", false)

	e, ok := joiner.last().Payload.(*pb.ServerMessage_Error)
	if !ok || e.Error.Message != "PEER_REJECTED" {
		t.Fatalf("joiner not notified of rejection: %v", joiner.last())
	}
}

func TestForwardRequiresPair(t *testing.T) {
	r := newRelay(newFakeStore())
	attach(t, r, "a")
	attach(t, r, "b")
	msg := &pb.ServerMessage{Payload: &pb.ServerMessage_ChatMessage{ChatMessage: &pb.EncryptedPayload{Nonce: []byte("n")}}}

	if err := r.Forward("a", msg); err == nil {
		t.Fatal("forward without a pair must fail")
	}

	x, kem := validKeys("a")
	_ = r.Register("a", "room1", x, kem)
	_ = r.Find("b", "room1", x, kem)
	_ = r.Accept("a", true)

	bPeer := r.peers["b"].peer.(*fakePeer)
	before := bPeer.count()
	if err := r.Forward("a", msg); err != nil {
		t.Fatalf("forward with pair: %v", err)
	}
	if bPeer.count() != before+1 {
		t.Fatal("message was not forwarded")
	}
}

func TestDetachNotifiesPeer(t *testing.T) {
	r := newRelay(newFakeStore())
	attach(t, r, "a")
	b := attach(t, r, "b")
	x, kem := validKeys("a")
	_ = r.Register("a", "room1", x, kem)
	_ = r.Find("b", "room1", x, kem)
	_ = r.Accept("a", true)

	r.Detach("a")
	e, ok := b.last().Payload.(*pb.ServerMessage_Error)
	if !ok || e.Error.Message != "PEER_DISCONNECTED" {
		t.Fatalf("peer not notified of disconnect: %v", b.last())
	}
}

func TestPendingExpires(t *testing.T) {
	r := newRelay(newFakeStore())
	now := time.Now()
	r.now = func() time.Time { return now }
	owner := attach(t, r, "owner")
	joiner := attach(t, r, "joiner")
	x, kem := validKeys("a")
	_ = r.Register("owner", "room1", x, kem)
	_ = r.Find("joiner", "room1", x, kem)

	now = now.Add(pendingTTL + time.Second)
	r.Sweep()

	for name, p := range map[string]*fakePeer{"joiner": joiner, "owner": owner} {
		e, ok := p.last().Payload.(*pb.ServerMessage_Error)
		if !ok || e.Error.Message != "PEER_LEFT" {
			t.Fatalf("expired %s not notified: %v", name, p.last())
		}
	}
}

func TestValidationRejectsBadInput(t *testing.T) {
	r := newRelay(newFakeStore())
	attach(t, r, "a")
	x, kem := validKeys("a")

	if err := r.Register("a", "ab", x, kem); err == nil {
		t.Fatal("short keyword accepted")
	}
	if err := r.Register("a", "has space", x, kem); err == nil {
		t.Fatal("invalid keyword accepted")
	}
	if err := r.Register("a", "room1", "short", kem); err == nil {
		t.Fatal("short x25519 key accepted")
	}
	if err := r.Register("a", "room1", x, "short"); err == nil {
		t.Fatal("short kem key accepted")
	}
	if err := r.Register("a", "room1", strings.Repeat("z", 64), kem); err == nil {
		t.Fatal("non-hex x25519 key accepted")
	}
}

func TestRateLimitApplied(t *testing.T) {
	r := newRelay(newFakeStore())
	p := &fakePeer{}
	r.Attach("a", p, rate.NewLimiter(rate.Limit(1), 1), nil)
	x, kem := validKeys("a")

	if err := r.Register("a", "room1", x, kem); err != nil {
		t.Fatalf("first register should pass: %v", err)
	}
	if err := r.Register("a", "room2", x, kem); err == nil {
		t.Fatal("second register should be rate limited")
	}
}

// A paired peer must not be able to open a second room: accepting a second
// pairing would leave the pairs map inconsistent.
func TestRegisterRejectedWhilePaired(t *testing.T) {
	r := newRelay(newFakeStore())
	attach(t, r, "a")
	attach(t, r, "b")
	x, kem := validKeys("a")
	_ = r.Register("a", "room1", x, kem)
	_ = r.Find("b", "room1", x, kem)
	_ = r.Accept("a", true)

	if err := r.Register("a", "room2", x, kem); err == nil {
		t.Fatal("register while paired must be rejected")
	}
}

// A paired peer must not be able to Find another room either (SEC-002): the
// joiner of an established pair accepting a third party's room would create
// an asymmetric triangle.
func TestFindRejectedWhilePaired(t *testing.T) {
	r := newRelay(newFakeStore())
	attach(t, r, "a")
	attach(t, r, "b")
	attach(t, r, "c")
	x, kem := validKeys("a")
	_ = r.Register("a", "room1", x, kem)
	_ = r.Register("c", "room2", x, kem)
	_ = r.Find("b", "room1", x, kem)
	_ = r.Accept("a", true)

	if err := r.Find("b", "room2", x, kem); err == nil {
		t.Fatal("paired peer must not be able to find another room")
	}
}

// A peer awaiting a connection answer must not be able to register a room in
// between — the pending map is keyed by session and would be corrupted.
func TestRegisterRejectedWhilePending(t *testing.T) {
	r := newRelay(newFakeStore())
	attach(t, r, "owner")
	attach(t, r, "joiner")
	x, kem := validKeys("a")
	_ = r.Register("owner", "room1", x, kem)
	_ = r.Find("joiner", "room1", x, kem)

	if err := r.Register("joiner", "room2", x, kem); err == nil {
		t.Fatal("register while pending must be rejected")
	}
}

// Accept must refuse to install a pairing when either side became paired in
// the meantime (SEC-002).
func TestAcceptRejectedWhenJoinerPairedElsewhere(t *testing.T) {
	r := newRelay(newFakeStore())
	attach(t, r, "owner")
	attach(t, r, "joiner")
	x, kem := validKeys("a")
	_ = r.Register("owner", "room1", x, kem)
	_ = r.Find("joiner", "room1", x, kem)

	// The joiner gets paired through some other path while the request is
	// pending; only reachable by corrupting state here on purpose.
	r.mu.Lock()
	r.pairs["joiner"] = "z"
	r.pairs["z"] = "joiner"
	r.mu.Unlock()

	if err := r.Accept("owner", true); err == nil {
		t.Fatal("accept must refuse when the joiner is paired elsewhere")
	}

	r.mu.Lock()
	_, ownerPaired := r.pairs["owner"]
	r.mu.Unlock()
	if ownerPaired {
		t.Fatal("refused accept must not pair the owner")
	}
}

// A failed room claim must not flip the peer's ownership to the contested
// keyword, and the subsequent Detach must not delete the rightful owner's
// room (SEC-003).
func TestFailedRegisterKeepsVictimRoom(t *testing.T) {
	store := newFakeStore()
	r := newRelay(store)
	attach(t, r, "victim")
	attach(t, r, "attacker")
	x, kem := validKeys("a")

	if err := r.Register("victim", "vroom", x, kem); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("attacker", "aroom", x, kem); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("attacker", "vroom", x, kem); err == nil {
		t.Fatal("claiming a taken room must fail")
	}

	r.Detach("attacker")
	if _, err := store.Get(context.Background(), roomKey("vroom")); err != nil {
		t.Fatal("failed claim must not release the victim's room")
	}
	if _, err := store.Get(context.Background(), roomKey("aroom")); err == nil {
		t.Fatal("attacker's own room must be released by their detach")
	}
}

// A keyword that expired and was reclaimed by a new owner must survive the
// previous owner's disconnect (SEC-003).
func TestDetachDoesNotDeleteReclaimedRoom(t *testing.T) {
	store := newFakeStore()
	r := newRelay(store)
	attach(t, r, "a")
	x, kem := validKeys("a")

	_ = r.Register("a", "kw", x, kem)
	// Simulate TTL expiry and re-claim by "b".
	ctx := context.Background()
	_ = store.Del(ctx, roomKey("kw"))
	if ok, err := store.SetNX(ctx, roomKey("kw"), encodeRoom(roomValue{SessionID: "b", X25519: x, KEM: kem}), roomTTL); !ok || err != nil {
		t.Fatal("re-claim setup failed")
	}

	r.Detach("a")
	if _, err := store.Get(ctx, roomKey("kw")); err != nil {
		t.Fatal("reclaimed room must not be deleted by its previous owner")
	}
}

// Re-registering a different keyword must release the old room so it does not
// linger in the store until its TTL expires.
func TestReregisterReleasesOldRoom(t *testing.T) {
	store := newFakeStore()
	r := newRelay(store)
	attach(t, r, "a")
	x, kem := validKeys("a")

	if err := r.Register("a", "room1", x, kem); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("a", "room2", x, kem); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), roomKey("room1")); err == nil {
		t.Fatal("old room must be deleted on re-register")
	}
}

// Chat forwarding has its own, much higher allowance: a signaling-rate
// limiter must not throttle conversation, but a flood must still be stopped.
func TestForwardHasSeparateRateLimit(t *testing.T) {
	r := newRelay(newFakeStore())
	attach(t, r, "a")
	b := attach(t, r, "b")
	r.peers["a"].signaling = rate.NewLimiter(rate.Limit(1), 1)
	r.peers["a"].data = rate.NewLimiter(rate.Inf, 0)
	x, kem := validKeys("a")
	_ = r.Register("a", "room1", x, kem)
	_ = r.Find("b", "room1", x, kem)
	_ = r.Accept("a", true)

	msg := &pb.ServerMessage{Payload: &pb.ServerMessage_ChatMessage{ChatMessage: &pb.EncryptedPayload{Nonce: []byte("n")}}}
	for i := 0; i < 10; i++ {
		if err := r.Forward("a", msg); err != nil {
			t.Fatalf("message %d throttled by signaling limiter: %v", i, err)
		}
	}

	r.peers["a"].data = rate.NewLimiter(rate.Limit(1), 1)
	if err := r.Forward("a", msg); err != nil {
		t.Fatalf("first message after refill: %v", err)
	}
	if err := r.Forward("a", msg); err == nil {
		t.Fatal("data flood must be throttled")
	}
	if b.count() == 0 {
		t.Fatal("peer received nothing")
	}
}
