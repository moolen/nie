test:
	@packages=$$(go list ./...); \
	if [ -z "$$packages" ]; then \
		echo "no packages to test"; \
	else \
		go test ./...; \
	fi

generate:
	go generate ./internal/ebpf

build:
	go build ./cmd/nie

test-integration:
	sudo -E go test -tags=integration ./test/...
