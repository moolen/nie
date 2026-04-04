#!/usr/bin/env bash
set -euo pipefail

cd /home/vagrant/nie

export PATH="/usr/local/go/bin:${PATH}"

make generate
go test ./...
env \
  NIE_VM_E2E="${NIE_VM_E2E:-}" \
  NIE_VM_FIXTURE_ADDR="${NIE_VM_FIXTURE_ADDR:-}" \
  NIE_VM_ALLOWED_HOST="${NIE_VM_ALLOWED_HOST:-}" \
  go test -tags=integration ./test/... -v
