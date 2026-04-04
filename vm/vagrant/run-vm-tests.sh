#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE_ADDR="${NIE_VM_FIXTURE_ADDR:-192.168.56.1:18080}"
ALLOWED_HOST="${NIE_VM_ALLOWED_HOST:-allowed.vm.test}"

cleanup() {
  if [[ -n "${fixture_pid:-}" ]]; then
    kill "${fixture_pid}" >/dev/null 2>&1 || true
    wait "${fixture_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

cd "${ROOT}"
go run ./vm/vagrant/fixture -listen "${FIXTURE_ADDR}" >/tmp/nie-vm-fixture.log 2>&1 &
fixture_pid=$!

cd vm/vagrant
vagrant validate
vagrant up --provider=virtualbox --provision
vagrant ssh -c "cd /home/vagrant/nie && sudo -E env NIE_VM_E2E=1 NIE_VM_FIXTURE_ADDR=${FIXTURE_ADDR} NIE_VM_ALLOWED_HOST=${ALLOWED_HOST} ./vm/vagrant/run-tests.sh"
