.PHONY: test generate build test-integration vm-test

test:
	go test ./...

generate:
	go generate ./internal/ebpf

build:
	go build ./cmd/nie

test-integration:
	sudo -E go test -tags=integration ./test/...

vm-test:
	./vm/vagrant/run-vm-tests.sh
