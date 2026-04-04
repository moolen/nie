#!/usr/bin/env bash
set -euo pipefail

cd /home/vagrant/nie

export PATH="/usr/local/go/bin:${PATH}"

make generate
go test ./...
go test -tags=integration ./test/... -v
