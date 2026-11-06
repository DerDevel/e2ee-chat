.PHONY: proto build test race vet lint fmt certs smoke tidy clean

# Regenerate Go code from proto/chat.proto. Requires protoc and the Go plugins:
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/chat.proto

build:
	go build ./...

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run

fmt:
	gofmt -w client server internal

# Generate a local development certificate and print its pin.
certs:
	./scripts/gen-certs.sh

# Full end-to-end smoke test: fake Redis + real server + two real clients
# in pseudo-terminals, including a re-pair round. Needs go, openssl, python3.
smoke:
	python3 scripts/smoke-e2e.py

# Minimal in-memory Redis stand-in for local development without Docker.
dev-redis:
	python3 scripts/dev-redis.py

tidy:
	go mod tidy

clean:
	rm -f client/client server/server
