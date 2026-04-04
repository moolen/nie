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
	cd vm/vagrant && vagrant validate
	cd vm/vagrant && vagrant up --provider=virtualbox --provision
	cd vm/vagrant && vagrant ssh -c 'cd /home/vagrant/nie && sudo -E ./vm/vagrant/run-tests.sh'
