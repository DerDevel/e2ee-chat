package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	pb "e2ee-chat/proto"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type server struct {
	pb.UnimplementedChatServiceServer
	rdb     *redis.Client
	mu      sync.Mutex
	streams map[string]pb.ChatService_ConnectServer
	pairs   map[string]string
}

func NewServer(rdb *redis.Client) *server {
	return &server{
		rdb:     rdb,
		streams: make(map[string]pb.ChatService_ConnectServer),
		pairs:   make(map[string]string),
	}
}

func (s *server) Connect(stream pb.ChatService_ConnectServer) error {
	sessionID := fmt.Sprintf("sess_%d", time.Now().UnixNano())

	s.mu.Lock()
	s.streams[sessionID] = stream
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.streams, sessionID)

		var peerStream pb.ChatService_ConnectServer
		var hasPeer bool

		if peerID, ok := s.pairs[sessionID]; ok {
			delete(s.pairs, sessionID)
			delete(s.pairs, peerID)
			peerStream = s.streams[peerID]
			hasPeer = true
		}

		if peerID, ok := s.pairs[sessionID+"_pending"]; ok {
			delete(s.pairs, sessionID+"_pending")
			delete(s.pairs, peerID+"_pending")
			delete(s.pairs, sessionID+"_pending_pub")
			delete(s.pairs, peerID+"_pending_pub")
			delete(s.pairs, peerID+"_pending_keyword")
		}
		s.mu.Unlock()

		if hasPeer && peerStream != nil {
			peerStream.Send(&pb.ServerMessage{Payload: &pb.ServerMessage_Error{Error: &pb.Error{Message: "PEER_DISCONNECTED"}}})
		}
	}()

	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}

		switch payload := msg.Payload.(type) {
		case *pb.ClientMessage_RegisterRoom:
			ctx := context.Background()
			data, _ := json.Marshal(map[string]string{
				"sid":     sessionID,
				"pub_key": payload.RegisterRoom.PublicKey,
			})
			s.rdb.Set(ctx, "room:"+payload.RegisterRoom.Keyword, data, 5*time.Minute)

		case *pb.ClientMessage_FindRoom:
			ctx := context.Background()
			data, err := s.rdb.Get(ctx, "room:"+payload.FindRoom.Keyword).Bytes()
			if err != nil {
				stream.Send(&pb.ServerMessage{Payload: &pb.ServerMessage_Error{Error: &pb.Error{Message: "Комната не найдена"}}})
				continue
			}

			var peerData map[string]string
			json.Unmarshal(data, &peerData)
			peerSessionID := peerData["sid"]
			peerPubKey := peerData["pub_key"]

			s.mu.Lock()
			_, isConnected := s.pairs[peerSessionID]
			_, isPending := s.pairs[peerSessionID+"_pending"]
			if isConnected || isPending {
				s.mu.Unlock()
				stream.Send(&pb.ServerMessage{Payload: &pb.ServerMessage_Error{Error: &pb.Error{Message: "Комната уже занята"}}})
				continue
			}

			peerStream := s.streams[peerSessionID]
			s.pairs[sessionID+"_pending"] = peerSessionID
			s.pairs[peerSessionID+"_pending"] = sessionID
			s.pairs[sessionID+"_pending_pub"] = peerPubKey
			s.pairs[peerSessionID+"_pending_pub"] = payload.FindRoom.PublicKey
			s.pairs[peerSessionID+"_pending_keyword"] = payload.FindRoom.Keyword
			s.mu.Unlock()

			if peerStream != nil {
				peerStream.Send(&pb.ServerMessage{
					Payload: &pb.ServerMessage_IncomingRequest{IncomingRequest: &pb.IncomingConnectionRequest{PeerPublicKey: payload.FindRoom.PublicKey}},
				})
			}

		case *pb.ClientMessage_AcceptConnection:
			s.mu.Lock()
			peerSessionID := s.pairs[sessionID+"_pending"]
			peerBPubKey := s.pairs[sessionID+"_pending_pub"]
			peerAPubKey := s.pairs[peerSessionID+"_pending_pub"]
			keyword := s.pairs[peerSessionID+"_pending_keyword"]
			peerStream := s.streams[peerSessionID]

			if payload.AcceptConnection.Accepted && peerSessionID != "" {
				s.pairs[sessionID] = peerSessionID
				s.pairs[peerSessionID] = sessionID

				delete(s.pairs, sessionID+"_pending")
				delete(s.pairs, peerSessionID+"_pending")
				delete(s.pairs, sessionID+"_pending_pub")
				delete(s.pairs, peerSessionID+"_pending_pub")
				delete(s.pairs, peerSessionID+"_pending_keyword")
			} else {
				peerSessionID = ""
			}
			s.mu.Unlock()

			if peerSessionID != "" {
				stream.Send(&pb.ServerMessage{
					Payload: &pb.ServerMessage_ConnectionEstablished{ConnectionEstablished: &pb.ConnectionEstablished{PeerPublicKey: peerBPubKey}},
				})

				if peerStream != nil {
					peerStream.Send(&pb.ServerMessage{
						Payload: &pb.ServerMessage_ConnectionEstablished{ConnectionEstablished: &pb.ConnectionEstablished{PeerPublicKey: peerAPubKey}},
					})
				}

				if keyword != "" {
					s.rdb.Del(context.Background(), "room:"+keyword)
				}
			}

		case *pb.ClientMessage_ChatMessage:
			s.mu.Lock()
			peerSessionID, ok := s.pairs[sessionID]
			var peerStream pb.ChatService_ConnectServer
			if ok {
				peerStream = s.streams[peerSessionID]
			}
			s.mu.Unlock()

			if peerStream != nil {
				peerStream.Send(&pb.ServerMessage{Payload: &pb.ServerMessage_ChatMessage{ChatMessage: payload.ChatMessage}})
			}
		}
	}
}

func main() {
	// ЗАГРУЗКА TLS СЕРТИФИКАТА
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("Не удалось загрузить сертификаты: %v. Сгенерируйте их командой openssl.", err)
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert, // Сервер не требует сертификат от клиента, но клиент будет проверять сервер
	})

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
	})

	// НОВАЯ ПРОВЕРКА: Пингуем Redis при старте
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("ОШИБКА ПОДКЛЮЧЕНИЯ К REDIS: %v", err)
	} else {
		log.Println("✅ Успешно подключились к Redis!")
	}

	// ПЕРЕДАЕМ TLS УЧЕТНЫЕ ДАННЫЕ В gRPC
	s := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterChatServiceServer(s, NewServer(rdb))

	log.Println("Сервер запущен на :50051 (с TLS)")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
