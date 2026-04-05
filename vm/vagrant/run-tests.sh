#!/usr/bin/env bash
set -euo pipefail

cd /home/vagrant/nie

export PATH="/usr/local/go/bin:${PATH}"

if [[ -n "${NIE_VM_FIXTURE_ADDR:-}" ]]; then
  fixture_host="${NIE_VM_FIXTURE_ADDR%:*}"
  fixture_iface="$(ip -4 route get "${fixture_host}" | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit }}')"
  if [[ -n "${fixture_iface}" ]]; then
    sysctl -q -w "net.ipv6.conf.${fixture_iface}.disable_ipv6=1"
  fi
fi

make generate
go test ./...
env \
  NIE_VM_E2E="${NIE_VM_E2E:-}" \
  NIE_VM_FIXTURE_ADDR="${NIE_VM_FIXTURE_ADDR:-}" \
  NIE_VM_FIXTURE_HTTPS_PORTS="${NIE_VM_FIXTURE_HTTPS_PORTS:-}" \
  NIE_VM_ALLOWED_HOST="${NIE_VM_ALLOWED_HOST:-}" \
  go test -tags=integration ./test -run 'TestVM|TestReadVMNieWaitResult|TestStopVMProbeRequiresCleanExit' -v
