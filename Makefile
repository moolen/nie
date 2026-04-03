test:
	go test ./...

generate:
	go generate ./internal/ebpf

build:
	go build ./cmd/nie

test-integration:
	sudo -E go test -tags=integration ./test/...
