// Command server is the signaling and relay node of the E2E encrypted chat.
//
// The server only ever sees the public keys exchanged during signaling and the
// opaque ciphertexts relayed between the two peers — message contents,
// nicknames and the session secret never reach it. Rooms are claimed
// atomically in Redis with a short TTL, connection identifiers are drawn from
// crypto/rand, and every stream write is serialized.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"e2ee-chat/internal/transport"
	pb "e2ee-chat/proto"

	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	maxMessageSize = 64 * 1024

	// Signaling operations hit Redis and mutate pairing state, so they get a
	// tight budget; relayed chat traffic is cheap and interactive, so it gets
	// a generous one.
	signalingBurst = 5
	dataBurst      = 60

	nonceLen = 12 // chacha20poly1305 nonce
)

var (
	signalingRate = rate.Every(2 * time.Second)
	dataRate      = rate.Every(33 * time.Millisecond) // ~30 msg/s
)

const (
	// Global and per-address caps on live chat sessions.
	maxConcurrentSessions = 1024
	maxSessionsPerIP      = 64
)

type config struct {
	listen        string
	redisAddr     string
	redisPassword string
	redisDB       int
	tlsCert       string
	tlsKey        string
	tlsClientCA   string
}

func loadConfig() config {
	db, _ := strconv.Atoi(os.Getenv("E2EE_REDIS_DB"))
	return config{
		listen:        envOr("E2EE_LISTEN", ":50051"),
		redisAddr:     envOr("E2EE_REDIS_ADDR", "127.0.0.1:6379"),
		redisPassword: os.Getenv("E2EE_REDIS_PASSWORD"),
		redisDB:       db,
		tlsCert:       envOr("E2EE_TLS_CERT", "server.crt"),
		tlsKey:        envOr("E2EE_TLS_KEY", "server.key"),
		tlsClientCA:   os.Getenv("E2EE_TLS_CLIENT_CA"),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// conn wraps a gRPC stream and serializes writes to it. gRPC streams do not
// permit concurrent Send calls, and peers may relay to a stream from several
// goroutines.
type conn struct {
	id     string
	stream pb.ChatService_ConnectServer
	mu     sync.Mutex
}

func (c *conn) Send(m *pb.ServerMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stream.Send(m)
}

type server struct {
	pb.UnimplementedChatServiceServer
	relay *relay

	// sem bounds concurrent chat sessions; ips bounds them per client
	// address. Together they stop unauthenticated mass-connection resource
	// exhaustion.
	sem chan struct{}
	ips *ipGauge
}

// ipGauge counts live streams per client IP. Entries are removed as streams
// end, so the map is bounded by concurrently connected addresses.
type ipGauge struct {
	mu  sync.Mutex
	per map[string]int
}

func newIPGauge() *ipGauge { return &ipGauge{per: make(map[string]int)} }

func (g *ipGauge) acquire(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.per[ip] >= maxSessionsPerIP {
		return false
	}
	g.per[ip]++
	return true
}

func (g *ipGauge) release(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n := g.per[ip]; n <= 1 {
		delete(g.per, ip)
	} else {
		g.per[ip] = n - 1
	}
}

func hostFrom(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}

func (s *server) Connect(stream pb.ChatService_ConnectServer) error {
	host := hostFrom(stream.Context())
	if !s.ips.acquire(host) {
		return status.Error(codes.ResourceExhausted, "too many connections from this address")
	}
	defer s.ips.release(host)

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		return status.Error(codes.ResourceExhausted, "server busy")
	}

	id, err := newSessionID()
	if err != nil {
		return status.Error(codes.Internal, "could not allocate session")
	}
	c := &conn{id: id, stream: stream}
	// Allow a small burst of signaling operations, then throttle. This makes
	// keyword brute-forcing and room enumeration expensive. Chat forwarding is
	// throttled separately with a much higher allowance.
	s.relay.Attach(id, c,
		rate.NewLimiter(signalingRate, signalingBurst),
		rate.NewLimiter(dataRate, dataBurst))
	defer s.relay.Detach(id)

	slog.Debug("client connected", "session", id)

	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}

		switch p := msg.Payload.(type) {
		case *pb.ClientMessage_RegisterRoom:
			if err := s.relay.Register(id, p.RegisterRoom.Keyword, p.RegisterRoom.PublicKey, p.RegisterRoom.KemPublicKey); err != nil {
				_ = c.Send(userErr(err))
			}

		case *pb.ClientMessage_FindRoom:
			if err := s.relay.Find(id, p.FindRoom.Keyword, p.FindRoom.PublicKey, p.FindRoom.KemPublicKey); err != nil {
				_ = c.Send(userErr(err))
			}

		case *pb.ClientMessage_AcceptConnection:
			if err := s.relay.Accept(id, p.AcceptConnection.Accepted); err != nil {
				_ = c.Send(userErr(err))
			}

		case *pb.ClientMessage_ChatMessage:
			// Structural checks only: the payload is opaque ciphertext, but
			// the frame must be well-formed before it is relayed.
			if cm := p.ChatMessage; cm == nil ||
				len(cm.Nonce) != nonceLen ||
				len(cm.Ciphertext) < 16 { // AEAD tag
				_ = c.Send(errMsg("Некорректное сообщение"))
				continue
			}
			if err := s.relay.Forward(id, &pb.ServerMessage{
				Payload: &pb.ServerMessage_ChatMessage{ChatMessage: p.ChatMessage},
			}); err != nil {
				_ = c.Send(userErr(err))
			}

		case *pb.ClientMessage_KemCiphertext:
			if kc := p.KemCiphertext; kc == nil || len(kc.Ciphertext) != KemCiphertextLen {
				_ = c.Send(errMsg("Некорректный KEM ciphertext"))
				continue
			}
			if err := s.relay.Forward(id, &pb.ServerMessage{
				Payload: &pb.ServerMessage_KemCiphertext{KemCiphertext: p.KemCiphertext},
			}); err != nil {
				_ = c.Send(userErr(err))
			}
		}
	}
}

func newSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// userMessage maps relay sentinel errors to the strings shown in the client
// TUI. Unknown errors become a generic message so internals never leak.
func userMessage(err error) string {
	switch {
	case errors.Is(err, errBadKeyword):
		return "Некорректное кодовое слово (3-64 символа: a-z, A-Z, 0-9, . _ -)"
	case errors.Is(err, errBadKeys):
		return "Некорректные публичные ключи"
	case errors.Is(err, errRateSignaling):
		return "Слишком много запросов, попробуйте позже"
	case errors.Is(err, errRateData):
		return "Слишком много сообщений, попробуйте позже"
	case errors.Is(err, errRoomExists):
		return "Комната уже существует"
	case errors.Is(err, errRoomNotFound):
		return "Комната не найдена"
	case errors.Is(err, errRoomBusy):
		return "Комната уже занята"
	case errors.Is(err, errSelfJoin):
		return "Нельзя подключиться к собственной комнате"
	case errors.Is(err, errAlreadyPaired):
		return "Сначала завершите текущее соединение"
	case errors.Is(err, errAlreadyWait):
		return "Вы уже ожидаете соединение"
	case errors.Is(err, errNoIncoming):
		return "Нет входящего запроса"
	case errors.Is(err, errNoPair):
		return "Нет активного соединения"
	default:
		return "Внутренняя ошибка сервера"
	}
}

func userErr(err error) *pb.ServerMessage {
	return errMsg(userMessage(err))
}

type redisStore struct{ rdb *redis.Client }

// cmpDel deletes a key only while its value still carries the expected owner
// prefix, atomically (SEC-003).
var cmpDel = redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if v == false then return 0 end
if string.sub(v, 1, string.len(ARGV[1])) == ARGV[1] then
	return redis.call('DEL', KEYS[1])
end
return 0
`)

func (s redisStore) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return s.rdb.SetNX(ctx, key, value, ttl).Result()
}

func (s redisStore) Get(ctx context.Context, key string) ([]byte, error) {
	return s.rdb.Get(ctx, key).Bytes()
}

func (s redisStore) Del(ctx context.Context, key string) error {
	return s.rdb.Del(ctx, key).Err()
}

func (s redisStore) CompareDelete(ctx context.Context, key string, ownerPrefix string) error {
	return cmpDel.Run(ctx, s.rdb, []string{key}, ownerPrefix).Err()
}

func recoveryInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("recovered from panic in handler", "method", info.FullMethod, "panic", r)
			err = status.Error(codes.Internal, "internal error")
		}
	}()
	return handler(srv, ss)
}

func main() {
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	cfg := loadConfig()

	creds, err := transport.ServerTLSConfig(transport.ServerOptions{
		CertFile:     cfg.tlsCert,
		KeyFile:      cfg.tlsKey,
		ClientCAFile: cfg.tlsClientCA,
	})
	if err != nil {
		return err
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.redisAddr,
		Password: cfg.redisPassword,
		DB:       cfg.redisDB,
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		cancel()
		return errors.New("redis unavailable: " + err.Error())
	}
	cancel()
	slog.Info("connected to redis", "addr", cfg.redisAddr)

	r := newRelay(redisStore{rdb: rdb})

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(creds)),
		grpc.MaxRecvMsgSize(maxMessageSize),
		grpc.MaxSendMsgSize(maxMessageSize),
		grpc.StreamInterceptor(recoveryInterceptor),
		// Keep long-lived idle streams alive through NATs and detect dead
		// peers; clients may ping at most every 20s without an open stream.
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    1 * time.Minute,
			Timeout: 20 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             20 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	pb.RegisterChatServiceServer(grpcServer, &server{
		relay: r,
		sem:   make(chan struct{}, maxConcurrentSessions),
		ips:   newIPGauge(),
	})

	lis, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return err
	}

	go func() {
		ticker := time.NewTicker(pendingTTL / 2)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.Sweep()
			}
		}
	}()

	serveErr := make(chan error, 1)
	go func() { serveErr <- grpcServer.Serve(lis) }()
	slog.Info("listening", "addr", cfg.listen, "mtls", cfg.tlsClientCA != "")

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
		done := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			grpcServer.Stop()
		}
		return nil
	case err := <-serveErr:
		return err
	}
}
