// Command client is the console front-end of the E2E encrypted chat.
//
// It generates an ephemeral hybrid key pair (X25519 + ML-KEM-768), negotiates
// a shared secret with exactly one peer through the relay, and encrypts every
// message locally with ChaCha20-Poly1305. The relay only ever forwards
// ciphertext and the public keys used for signaling.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"e2ee-chat/internal/e2ee"
	"e2ee-chat/internal/transport"
	pb "e2ee-chat/proto"

	tea "github.com/charmbracelet/bubbletea"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// app owns the crypto session and the gRPC stream. Every field that is touched
// from more than one goroutine is protected by mu; stream writes are
// additionally serialized by sendMu because gRPC forbids concurrent sends.
type app struct {
	mu      sync.Mutex
	session *e2ee.Session

	stream   pb.ChatService_ConnectClient
	nickname string

	sendMu sync.Mutex
}

func (a *app) setNickname(n string) {
	a.mu.Lock()
	a.nickname = n
	a.mu.Unlock()
}

// rotateSession replaces the crypto session with a fresh one unless the
// current one has never been used. A session whose keys were published to a
// peer can never be reused for another pairing, so every retry after a chat
// ended must start from new key material.
func (a *app) rotateSession() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.session.Started() {
		return nil
	}
	fresh, err := e2ee.NewSession()
	if err != nil {
		return err
	}
	old := a.session
	a.session = fresh
	old.Close()
	return nil
}

func (a *app) publicKeys() e2ee.KeyPair {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.session.PublicKeys()
}

func (a *app) send(m *pb.ClientMessage) error {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	return a.stream.Send(m)
}

func (a *app) exchangePeer(peer keyPair) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.session.ExchangePeerKeys(e2ee.KeyPair{X25519: peer.X, KEM: peer.KEM})
}

func main() {
	if err := run(); err != nil {
		// Error strings may embed server-controlled text; sanitize before
		// printing to the terminal (SEC-001).
		fmt.Fprintln(os.Stderr, "ошибка:", sanitize(err.Error(), maxTextRunes))
		os.Exit(1)
	}
}

// clientFlags holds the command-line configuration. Every flag falls back to
// its E2EE_* environment variable, so both styles work; flags win.
type clientFlags struct {
	addr       string
	serverName string
	caFile     string
	pin        string
	insecure   bool
}

func parseClientFlags() clientFlags {
	var f clientFlags
	flag.StringVar(&f.addr, "addr", envOr("E2EE_SERVER_ADDR", "localhost:50051"),
		"адрес сервера (env E2EE_SERVER_ADDR)")
	flag.StringVar(&f.serverName, "server-name", os.Getenv("E2EE_TLS_SERVER_NAME"),
		"ожидаемое имя в сертификате сервера (env E2EE_TLS_SERVER_NAME; по умолчанию — host из -addr)")
	flag.StringVar(&f.caFile, "ca", os.Getenv("E2EE_TLS_CA"),
		"PEM-бандл доверенного CA (env E2EE_TLS_CA)")
	flag.StringVar(&f.pin, "pin", os.Getenv("E2EE_TLS_PIN"),
		"SHA-256 pin сертификата сервера, hex (env E2EE_TLS_PIN)")
	flag.BoolVar(&f.insecure, "insecure", os.Getenv("E2EE_TLS_INSECURE") == "1",
		"отключить проверку TLS — только для локальной разработки! (env E2EE_TLS_INSECURE=1)")
	flag.Parse()

	if f.serverName == "" {
		host, _, err := net.SplitHostPort(f.addr)
		if err != nil {
			host = f.addr
		}
		f.serverName = host
	}
	return f
}

func run() error {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))

	fl := parseClientFlags()
	opts := transport.ClientOptions{
		ServerName: fl.serverName,
		CAFile:     fl.caFile,
		PinSHA256:  fl.pin,
		Insecure:   fl.insecure,
	}
	if opts.Insecure {
		slog.Warn("TLS verification disabled; dev use only")
	}
	tlsCfg, err := transport.ClientTLSConfig(opts)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conn, err := grpc.NewClient(fl.addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 15 * time.Second,
		}),
	)
	if err != nil {
		return fmt.Errorf("подключение к серверу: %w", err)
	}
	defer func() { _ = conn.Close() }()

	session, err := e2ee.NewSession()
	if err != nil {
		return err
	}

	stream, err := pb.NewChatServiceClient(conn).Connect(ctx)
	if err != nil {
		return fmt.Errorf("открытие потока: %w", err)
	}

	a := &app{session: session, stream: stream}
	// Close whichever session is live at exit — rotateSession() may have
	// replaced the original one (SEC-005).
	defer func() {
		a.mu.Lock()
		a.session.Close()
		a.mu.Unlock()
	}()
	cmdCh := make(chan string, 100)

	m := initialModel(cmdCh)
	p := tea.NewProgram(m, tea.WithAltScreen())

	go recvLoop(ctx, a, p)
	go cmdLoop(a, p, cmdCh)

	if _, err := p.Run(); err != nil {
		return err
	}
	close(cmdCh) // unblocks cmdLoop; the TUI no longer produces commands
	stop()
	return nil
}

// recvLoop reads server messages and drives the UI and the key agreement.
func recvLoop(ctx context.Context, a *app, p *tea.Program) {
	for {
		msg, err := a.stream.Recv()
		if err != nil {
			if ctx.Err() == nil {
				p.Send(systemMsg{"SERVER_DISCONNECTED"})
			}
			return
		}

		switch payload := msg.Payload.(type) {
		case *pb.ServerMessage_IncomingRequest:
			p.Send(systemMsg{"Входящий запрос на подключение."})
			p.Send(systemMsg{"REQUEST_INCOMING"})

		case *pb.ServerMessage_ConnectionEstablished:
			est := payload.ConnectionEstablished
			if err := a.exchangePeer(keyPair{X: est.PeerPublicKey, KEM: est.PeerKemPublicKey}); err != nil {
				p.Send(errorMsg{"Ошибка согласования ключей: " + err.Error()})
				continue
			}
			if a.isInitiator() {
				ct, err := a.initiate()
				if err != nil {
					p.Send(errorMsg{"Ошибка установки соединения: " + err.Error()})
					continue
				}
				if err := a.send(&pb.ClientMessage{Payload: &pb.ClientMessage_KemCiphertext{
					KemCiphertext: &pb.KemCiphertext{Ciphertext: ct},
				}}); err != nil {
					p.Send(errorMsg{"Ошибка отправки: " + err.Error()})
					continue
				}
				a.sendNickname(p)
				p.Send(systemMsg{"CONNECTED"})
				a.sendSafetyCode(p)
			} else {
				p.Send(systemMsg{"Согласование ключей..."})
				p.Send(systemMsg{"HANDSHAKE_WAIT"})
			}

		case *pb.ServerMessage_KemCiphertext:
			if err := a.completeHandshake(payload.KemCiphertext.Ciphertext); err != nil {
				p.Send(errorMsg{"Ошибка согласования ключей: " + err.Error()})
				continue
			}
			a.sendNickname(p)
			p.Send(systemMsg{"CONNECTED"})
			a.sendSafetyCode(p)

		case *pb.ServerMessage_ChatMessage:
			nick, text, err := a.decrypt(payload.ChatMessage.Nonce, payload.ChatMessage.Ciphertext)
			if err != nil {
				p.Send(errorMsg{"Не удалось расшифровать сообщение: " + err.Error()})
				continue
			}
			// Everything rendered comes from the peer; strip terminal
			// control sequences before it reaches the view.
			nick, text = sanitize(nick, maxNickRunes), sanitize(text, maxTextRunes)
			if text == "" && nick != "" {
				p.Send(systemMsg{"Собеседник " + nick + " в сети"})
			} else {
				p.Send(chatMsg{nick: nick, text: text})
			}

		case *pb.ServerMessage_Error:
			// The message text is relay/server-controlled; strip terminal
			// control sequences before it reaches the view (SEC-001).
			msg := sanitize(payload.Error.Message, maxTextRunes)
			switch payload.Error.Message {
			case "PEER_DISCONNECTED", "PEER_LEFT":
				p.Send(systemMsg{"PEER_LEFT"})
			case "PEER_REJECTED":
				p.Send(systemMsg{"PEER_REJECTED"})
			default:
				p.Send(errorMsg{msg})
			}
		}
	}
}

func cmdLoop(a *app, p *tea.Program, cmdCh chan string) {
	for cmd := range cmdCh {
		switch {
		case strings.HasPrefix(cmd, "nick:"):
			a.setNickname(sanitize(strings.TrimPrefix(cmd, "nick:"), maxNickRunes))
		case strings.HasPrefix(cmd, "register:"), strings.HasPrefix(cmd, "find:"):
			// A session whose keys were already shown to a peer cannot be
			// reused; start from fresh key material every new pairing.
			if err := a.rotateSession(); err != nil {
				p.Send(errorMsg{"Не удалось создать сессию: " + err.Error()})
				continue
			}
			keys := a.publicKeys()
			var m *pb.ClientMessage
			if kw := strings.TrimPrefix(cmd, "register:"); cmd != kw {
				m = &pb.ClientMessage{Payload: &pb.ClientMessage_RegisterRoom{
					RegisterRoom: &pb.RegisterRoomRequest{Keyword: kw, PublicKey: keys.X25519, KemPublicKey: keys.KEM},
				}}
			} else {
				kw := strings.TrimPrefix(cmd, "find:")
				m = &pb.ClientMessage{Payload: &pb.ClientMessage_FindRoom{
					FindRoom: &pb.FindRoomRequest{Keyword: kw, PublicKey: keys.X25519, KemPublicKey: keys.KEM},
				}}
			}
			if err := a.send(m); err != nil {
				p.Send(errorMsg{"Ошибка отправки: " + err.Error()})
			}
		case cmd == "accept":
			_ = a.send(&pb.ClientMessage{Payload: &pb.ClientMessage_AcceptConnection{
				AcceptConnection: &pb.AcceptConnectionRequest{Accepted: true},
			}})
		case cmd == "reject":
			_ = a.send(&pb.ClientMessage{Payload: &pb.ClientMessage_AcceptConnection{
				AcceptConnection: &pb.AcceptConnectionRequest{Accepted: false},
			}})
		case strings.HasPrefix(cmd, "msg:"):
			txt := strings.TrimPrefix(cmd, "msg:")
			if utf8.RuneCountInString(txt) > maxTextRunes {
				p.Send(errorMsg{"Слишком длинное сообщение (максимум 2000 символов)"})
				continue
			}
			nonce, ct, err := a.encryptMsg(txt)
			if err != nil {
				p.Send(errorMsg{"Ошибка шифрования: " + err.Error()})
				continue
			}
			if err := a.send(&pb.ClientMessage{Payload: &pb.ClientMessage_ChatMessage{
				ChatMessage: &pb.EncryptedPayload{Nonce: nonce, Ciphertext: ct},
			}}); err != nil {
				p.Send(errorMsg{"Ошибка отправки: " + err.Error()})
			}
		}
	}
}

// The helpers below serialize access to the crypto session.

func (a *app) isInitiator() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.session.Initiator()
}

func (a *app) initiate() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.session.Initiate()
}

func (a *app) completeHandshake(ct []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.session.Complete(ct)
}

// sendNickname announces presence: an encrypted frame with the nickname and an
// empty body. The peer displays it as an online notification.
func (a *app) sendNickname(p *tea.Program) {
	nonce, ct, err := a.encryptMsg("")
	if err != nil {
		return
	}
	if err := a.send(&pb.ClientMessage{Payload: &pb.ClientMessage_ChatMessage{
		ChatMessage: &pb.EncryptedPayload{Nonce: nonce, Ciphertext: ct},
	}}); err != nil {
		p.Send(errorMsg{"Ошибка отправки: " + err.Error()})
	}
}

func (a *app) sendSafetyCode(p *tea.Program) {
	a.mu.Lock()
	code, err := a.session.SafetyCode()
	a.mu.Unlock()
	if err != nil {
		return
	}
	p.Send(systemMsg{"Код безопасности: " + code})
	p.Send(systemMsg{"Сверьте код с собеседником. Несовпадение означает MITM-атаку."})
}

func (a *app) encryptMsg(text string) (nonce, ct []byte, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.session.Encrypt(e2ee.Payload{Nickname: a.nickname, Text: text})
}

func (a *app) decrypt(nonce, ct []byte) (string, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	payload, err := a.session.Decrypt(nonce, ct)
	if err != nil {
		return "", "", err
	}
	return payload.Nickname, payload.Text, nil
}

type keyPair struct {
	X, KEM string
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
