package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"strings"

	pb "e2ee-chat/proto"

	tea "github.com/charmbracelet/bubbletea"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	cm := NewCryptoManager()
	var myNickname string

	// ИСПОЛЬЗУЕМ СИСТЕМНЫЕ СЕРТИФИКАТЫ
	// Пустой конфиг TLS заставляет gRPC использовать доверенные корневые центры (CA) ОС.
	creds := credentials.NewTLS(&tls.Config{
		//ServerName: "localhost",
		InsecureSkipVerify: true,
	})

	// Подключаемся к домену (Nginx), а не к localhost!
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	client := pb.NewChatServiceClient(conn)

	stream, err := client.Connect(context.Background())
	if err != nil {
		log.Fatalf("could not connect: %v", err)
	}

	cmdCh := make(chan string, 100)

	m := initialModel(cmdCh)
	p := tea.NewProgram(m, tea.WithAltScreen())

	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				p.Send(systemMsg{"SERVER_DISCONNECTED"})
				return
			}

			switch payload := msg.Payload.(type) {
			case *pb.ServerMessage_IncomingRequest:
				cm.DeriveSharedKey(payload.IncomingRequest.PeerPublicKey)
				p.Send(systemMsg{"Входящий запрос на подключение."})
				p.Send(systemMsg{"REQUEST_INCOMING"})

			case *pb.ServerMessage_ConnectionEstablished:
				cm.DeriveSharedKey(payload.ConnectionEstablished.PeerPublicKey)

				// НОВОЕ: Вычисляем и выводим Код Безопасности
				safetyCode, _ := cm.GenerateSafetyCode(payload.ConnectionEstablished.PeerPublicKey)
				p.Send(systemMsg{"CONNECTED"})
				p.Send(systemMsg{"🔐 Код безопасности: " + safetyCode})
				p.Send(systemMsg{"(Сверьте этот код с собеседником. Если он совпадает - MITM атаки нет)"})

				nonce, cipher, _ := cm.Encrypt(myNickname, "")
				stream.Send(&pb.ClientMessage{
					Payload: &pb.ClientMessage_ChatMessage{
						ChatMessage: &pb.EncryptedPayload{Nonce: nonce, Ciphertext: cipher},
					},
				})

			case *pb.ServerMessage_ChatMessage:
				nick, text, err := cm.Decrypt(payload.ChatMessage.Nonce, payload.ChatMessage.Ciphertext)
				if err == nil {
					if text == "" && nick != "" {
						p.Send(systemMsg{"Собеседник " + nick + " в сети"})
					} else {
						p.Send(chatMsg{nick: nick, text: text})
					}
				}

			case *pb.ServerMessage_Error:
				if payload.Error.Message == "PEER_DISCONNECTED" {
					p.Send(systemMsg{"PEER_LEFT"})
				} else {
					p.Send(errorMsg{payload.Error.Message})
				}
			}
		}
	}()

	go func() {
		for cmd := range cmdCh {
			if strings.HasPrefix(cmd, "nick:") {
				myNickname = strings.TrimPrefix(cmd, "nick:")
			} else if strings.HasPrefix(cmd, "register:") {
				kw := strings.TrimPrefix(cmd, "register:")
				stream.Send(&pb.ClientMessage{
					Payload: &pb.ClientMessage_RegisterRoom{
						RegisterRoom: &pb.RegisterRoomRequest{Keyword: kw, PublicKey: cm.GetPublicKeyHex()},
					},
				})
			} else if strings.HasPrefix(cmd, "find:") {
				kw := strings.TrimPrefix(cmd, "find:")
				stream.Send(&pb.ClientMessage{
					Payload: &pb.ClientMessage_FindRoom{
						FindRoom: &pb.FindRoomRequest{Keyword: kw, PublicKey: cm.GetPublicKeyHex()},
					},
				})
			} else if cmd == "accept" {
				stream.Send(&pb.ClientMessage{
					Payload: &pb.ClientMessage_AcceptConnection{
						AcceptConnection: &pb.AcceptConnectionRequest{Accepted: true},
					},
				})
			} else if cmd == "reject" {
				stream.Send(&pb.ClientMessage{
					Payload: &pb.ClientMessage_AcceptConnection{
						AcceptConnection: &pb.AcceptConnectionRequest{Accepted: false},
					},
				})
			} else if strings.HasPrefix(cmd, "msg:") {
				txt := strings.TrimPrefix(cmd, "msg:")
				nonce, cipher, _ := cm.Encrypt(myNickname, txt)
				stream.Send(&pb.ClientMessage{
					Payload: &pb.ClientMessage_ChatMessage{
						ChatMessage: &pb.EncryptedPayload{Nonce: nonce, Ciphertext: cipher},
					},
				})
			}
		}
	}()

	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
}
