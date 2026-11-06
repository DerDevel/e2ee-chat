package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sync"
	"time"

	pb "e2ee-chat/proto"

	"golang.org/x/time/rate"
)

const (
	roomTTL    = 5 * time.Minute
	pendingTTL = 2 * time.Minute
	opTimeout  = 3 * time.Second
	x25519Hex  = 64   // 32 bytes
	kem768Hex  = 2368 // ML-KEM-768 encapsulation key, 1184 bytes

	// KemCiphertextLen is the exact size of a valid ML-KEM-768 ciphertext.
	KemCiphertextLen = 1088
)

// Peer is a connected client that can receive server messages. Sends must be
// serialized by the implementation.
type Peer interface {
	Send(*pb.ServerMessage) error
}

// roomStore is the minimal key/value contract the relay needs. It is satisfied
// by Redis in production and by an in-memory fake in tests. CompareDelete
// removes a key only while its value still carries the expected owner prefix:
// a keyword whose TTL expired and was reclaimed by someone else must never be
// deleted by the previous owner.
type roomStore interface {
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	Get(ctx context.Context, key string) ([]byte, error)
	Del(ctx context.Context, key string) error
	CompareDelete(ctx context.Context, key string, ownerPrefix string) error
}

type roomValue struct {
	SessionID string `json:"sid"`
	X25519    string `json:"x"`
	KEM       string `json:"kem"`
}

// encodeRoom stores a room as "<sessionID>|<json>" so ownership can be
// verified with a prefix comparison without parsing the payload.
func encodeRoom(v roomValue) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	out := make([]byte, 0, len(v.SessionID)+1+len(b))
	out = append(out, v.SessionID...)
	out = append(out, '|')
	return append(out, b...)
}

func decodeRoom(b []byte) (roomValue, error) {
	i := bytes.IndexByte(b, '|')
	if i <= 0 {
		return roomValue{}, errRoomNotFound
	}
	var v roomValue
	if err := json.Unmarshal(b[i+1:], &v); err != nil || v.SessionID == "" {
		return roomValue{}, errRoomNotFound
	}
	return v, nil
}

type peerState struct {
	peer Peer
	// signaling throttles room operations; data throttles relayed chat
	// traffic. Signaling is expensive to answer (Redis + pairing state) while
	// data forwarding is cheap, so data gets a much higher allowance.
	signaling *rate.Limiter
	data      *rate.Limiter
	room      string // keyword owned by this peer, if any
}

type pendingReq struct {
	ownerID   string
	joinerID  string
	ownerX    string
	ownerKEM  string
	joinerX   string
	joinerKEM string
	keyword   string
	expires   time.Time
}

func (p *pendingReq) other(id string) string {
	if id == p.ownerID {
		return p.joinerID
	}
	return p.ownerID
}

var keywordRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

// Sentinel errors carried to the gRPC layer, which maps them to user-facing
// messages. The relay itself stays free of UI strings.
var (
	errBadKeyword    = errors.New("bad keyword")
	errBadKeys       = errors.New("bad key material")
	errRateSignaling = errors.New("signaling rate limited")
	errRateData      = errors.New("data rate limited")
	errInternal      = errors.New("internal error")
	errRoomExists    = errors.New("room exists")
	errRoomNotFound  = errors.New("room not found")
	errRoomBusy      = errors.New("room busy")
	errSelfJoin      = errors.New("self join")
	errAlreadyPaired = errors.New("already paired")
	errAlreadyWait   = errors.New("already waiting")
	errNoIncoming    = errors.New("no incoming request")
	errNoPair        = errors.New("no active pair")
)

// relay holds all connection and pairing state. Every map mutation happens
// under mu; network sends happen outside the lock because Send may block.
type relay struct {
	store roomStore

	mu      sync.Mutex
	peers   map[string]*peerState
	pairs   map[string]string
	pending map[string]*pendingReq

	now func() time.Time
}

func newRelay(store roomStore) *relay {
	return &relay{
		store:   store,
		peers:   make(map[string]*peerState),
		pairs:   make(map[string]string),
		pending: make(map[string]*pendingReq),
		now:     time.Now,
	}
}

func roomKey(keyword string) string { return "room:" + keyword }

// releaseRoom deletes a room key only if the given session still owns it.
func (r *relay) releaseRoom(keyword, sessionID string) {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	_ = r.store.CompareDelete(ctx, roomKey(keyword), sessionID+"|")
}

// Attach registers a newly connected peer. The signaling limiter throttles
// room operations; the data limiter throttles relayed traffic. Either may be
// nil (or infinite) to disable throttling, which tests rely on.
func (r *relay) Attach(id string, p Peer, signaling, data *rate.Limiter) {
	r.mu.Lock()
	r.peers[id] = &peerState{peer: p, signaling: signaling, data: data}
	r.mu.Unlock()
}

// Detach removes a peer and notifies whoever it was paired or pending with.
func (r *relay) Detach(id string) {
	r.mu.Lock()
	ps := r.peers[id]
	delete(r.peers, id)

	var notify Peer
	var notifyMsg *pb.ServerMessage

	if pid, ok := r.pairs[id]; ok {
		delete(r.pairs, pid)
		delete(r.pairs, id)
		if peer := r.peers[pid]; peer != nil {
			notify = peer.peer
			notifyMsg = errMsg("PEER_DISCONNECTED")
		}
	}
	if p, ok := r.pending[id]; ok {
		other := p.other(id)
		delete(r.pending, p.ownerID)
		delete(r.pending, p.joinerID)
		if peer := r.peers[other]; peer != nil {
			notify = peer.peer
			notifyMsg = errMsg("PEER_LEFT")
		}
	}

	room := ""
	if ps != nil {
		room = ps.room
	}
	r.mu.Unlock()

	if notify != nil {
		_ = notify.Send(notifyMsg)
	}
	// Only a room this peer demonstrably owns is released; an expired and
	// reclaimed keyword must survive (SEC-003).
	if room != "" {
		r.releaseRoom(room, id)
	}
}

// Sweep drops expired pending requests and informs both affected peers.
func (r *relay) Sweep() {
	now := r.now()

	var notify []Peer
	seen := make(map[*pendingReq]bool)

	r.mu.Lock()
	for _, p := range r.pending {
		if seen[p] {
			continue
		}
		seen[p] = true
		if p.expires.After(now) {
			continue
		}
		delete(r.pending, p.ownerID)
		delete(r.pending, p.joinerID)
		// The joiner is still waiting for an answer; the owner may be sitting
		// in the accept prompt. Both need to learn the pairing is gone.
		if peer := r.peers[p.joinerID]; peer != nil {
			notify = append(notify, peer.peer)
		}
		if peer := r.peers[p.ownerID]; peer != nil {
			notify = append(notify, peer.peer)
		}
	}
	r.mu.Unlock()

	for _, p := range notify {
		_ = p.Send(errMsg("PEER_LEFT"))
	}
}

// Register claims a room keyword for the peer. It is atomic: a keyword already
// in use is rejected rather than overwritten. Registering while paired or
// while awaiting a connection answer is refused — a second pairing would
// corrupt the pairs map — and a successful re-registration releases any room
// the peer owned before. Room ownership flips only after the store claim
// succeeds, so a failed claim can never strand or delete someone else's room.
func (r *relay) Register(id, keyword, x, kem string) error {
	if err := validateKeyword(keyword); err != nil {
		return err
	}
	if err := validateKeyMaterial(x, kem); err != nil {
		return err
	}
	if !r.allowSignaling(id) {
		return errRateSignaling
	}

	var prevRoom string
	r.mu.Lock()
	if _, paired := r.pairs[id]; paired {
		r.mu.Unlock()
		return errAlreadyPaired
	}
	if _, pend := r.pending[id]; pend {
		r.mu.Unlock()
		return errAlreadyWait
	}
	if ps := r.peers[id]; ps != nil && ps.room != "" && ps.room != keyword {
		prevRoom = ps.room
	}
	r.mu.Unlock()

	val := encodeRoom(roomValue{SessionID: id, X25519: x, KEM: kem})
	if val == nil {
		return errInternal
	}

	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	ok, err := r.store.SetNX(ctx, roomKey(keyword), val, roomTTL)
	if err != nil {
		return errInternal
	}
	if !ok {
		// The claim failed: the peer keeps owning exactly what it owned
		// before (possibly nothing).
		return errRoomExists
	}

	// Claim succeeded — only now does the peer own the new keyword.
	r.mu.Lock()
	if ps := r.peers[id]; ps != nil {
		ps.room = keyword
	}
	r.mu.Unlock()

	if prevRoom != "" {
		r.releaseRoom(prevRoom, id)
	}
	return nil
}

// Find looks up a room and asks its owner to confirm the connection. A peer
// that is already paired may not look for another room: it could otherwise
// build asymmetric pairs (SEC-002).
func (r *relay) Find(id, keyword, x, kem string) error {
	if err := validateKeyword(keyword); err != nil {
		return err
	}
	if err := validateKeyMaterial(x, kem); err != nil {
		return err
	}
	if !r.allowSignaling(id) {
		return errRateSignaling
	}

	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	data, err := r.store.Get(ctx, roomKey(keyword))
	if err != nil {
		return errRoomNotFound
	}

	rv, err := decodeRoom(data)
	if err != nil {
		return errRoomNotFound
	}
	if rv.SessionID == id {
		return errSelfJoin
	}

	r.mu.Lock()
	if _, paired := r.pairs[id]; paired {
		r.mu.Unlock()
		return errAlreadyPaired
	}
	owner, ok := r.peers[rv.SessionID]
	if !ok {
		r.mu.Unlock()
		return errRoomNotFound
	}
	if _, paired := r.pairs[rv.SessionID]; paired {
		r.mu.Unlock()
		return errRoomBusy
	}
	if _, pend := r.pending[rv.SessionID]; pend {
		r.mu.Unlock()
		return errRoomBusy
	}
	if _, pend := r.pending[id]; pend {
		r.mu.Unlock()
		return errAlreadyWait
	}
	p := &pendingReq{
		ownerID: rv.SessionID, joinerID: id,
		ownerX: rv.X25519, ownerKEM: rv.KEM,
		joinerX: x, joinerKEM: kem,
		keyword: keyword, expires: r.now().Add(pendingTTL),
	}
	r.pending[id] = p
	r.pending[rv.SessionID] = p
	r.mu.Unlock()

	_ = owner.peer.Send(&pb.ServerMessage{
		Payload: &pb.ServerMessage_IncomingRequest{IncomingRequest: &pb.IncomingConnectionRequest{
			PeerPublicKey:    x,
			PeerKemPublicKey: kem,
		}},
	})
	return nil
}

// Accept resolves a pending request. Only the room owner may accept, and
// neither side may have become paired in the meantime — a stale pending must
// never install a second pairing over an existing one (SEC-002).
func (r *relay) Accept(id string, accepted bool) error {
	r.mu.Lock()
	p, ok := r.pending[id]
	if !ok || p.ownerID != id {
		r.mu.Unlock()
		return errNoIncoming
	}
	if _, paired := r.pairs[p.ownerID]; paired {
		delete(r.pending, p.ownerID)
		delete(r.pending, p.joinerID)
		r.mu.Unlock()
		return errAlreadyPaired
	}
	if _, paired := r.pairs[p.joinerID]; paired {
		delete(r.pending, p.ownerID)
		delete(r.pending, p.joinerID)
		r.mu.Unlock()
		return errAlreadyPaired
	}
	delete(r.pending, p.ownerID)
	delete(r.pending, p.joinerID)

	owner := r.peers[p.ownerID]
	joiner := r.peers[p.joinerID]
	if accepted {
		r.pairs[p.ownerID] = p.joinerID
		r.pairs[p.joinerID] = p.ownerID
		if owner != nil {
			owner.room = ""
		}
	}
	r.mu.Unlock()

	if !accepted {
		if joiner != nil {
			_ = joiner.peer.Send(errMsg("PEER_REJECTED"))
		}
		return nil
	}

	if owner != nil {
		_ = owner.peer.Send(established(p.joinerX, p.joinerKEM))
	}
	if joiner != nil {
		_ = joiner.peer.Send(established(p.ownerX, p.ownerKEM))
	}

	// The keyword may have expired and been reclaimed while the request was
	// pending; delete it only if this owner still holds it.
	r.releaseRoom(p.keyword, p.ownerID)
	return nil
}

// Forward relays an opaque server message to the peer this session is paired
// with. It is used for chat payloads and the KEM handshake. Relayed traffic is
// rate limited separately from signaling so a paired peer cannot flood its
// counterpart.
func (r *relay) Forward(id string, msg *pb.ServerMessage) error {
	if !r.allowData(id) {
		return errRateData
	}

	r.mu.Lock()
	peerID, ok := r.pairs[id]
	var peer *peerState
	if ok {
		peer = r.peers[peerID]
	}
	r.mu.Unlock()

	if !ok || peer == nil {
		return errNoPair
	}
	return peer.peer.Send(msg)
}

func (r *relay) allowSignaling(id string) bool {
	r.mu.Lock()
	ps := r.peers[id]
	r.mu.Unlock()
	if ps == nil || ps.signaling == nil {
		return true
	}
	return ps.signaling.Allow()
}

func (r *relay) allowData(id string) bool {
	r.mu.Lock()
	ps := r.peers[id]
	r.mu.Unlock()
	if ps == nil || ps.data == nil {
		return true
	}
	return ps.data.Allow()
}

func validateKeyword(keyword string) error {
	if !keywordRe.MatchString(keyword) {
		return errBadKeyword
	}
	return nil
}

func validateKeyMaterial(x, kem string) error {
	if len(x) != x25519Hex {
		return errBadKeys
	}
	if _, err := hex.DecodeString(x); err != nil {
		return errBadKeys
	}
	if len(kem) != kem768Hex {
		return errBadKeys
	}
	if _, err := hex.DecodeString(kem); err != nil {
		return errBadKeys
	}
	return nil
}

func errMsg(text string) *pb.ServerMessage {
	return &pb.ServerMessage{Payload: &pb.ServerMessage_Error{Error: &pb.Error{Message: text}}}
}

func established(x, kem string) *pb.ServerMessage {
	return &pb.ServerMessage{Payload: &pb.ServerMessage_ConnectionEstablished{
		ConnectionEstablished: &pb.ConnectionEstablished{
			PeerPublicKey:    x,
			PeerKemPublicKey: kem,
		},
	}}
}
