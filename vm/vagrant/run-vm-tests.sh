#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE_ADDR="${NIE_VM_FIXTURE_ADDR:-192.168.56.1:18080}"
ALLOWED_HOST="${NIE_VM_ALLOWED_HOST:-allowed.vm.test}"
TMPDIR_ROOT="${TMPDIR:-/tmp}"

tmpdir="$(mktemp -d "${TMPDIR_ROOT}/nie-vm-tests.XXXXXX")"
fixture_bin="${tmpdir}/fixture"
fixture_log="${tmpdir}/fixture.log"
fixture_url="http://${FIXTURE_ADDR}/healthz"

cleanup() {
  if [[ -n "${fixture_pid:-}" ]]; then
    kill "${fixture_pid}" >/dev/null 2>&1 || true
    wait "${fixture_pid}" 2>/dev/null || true
  fi
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

wait_for_fixture() {
  local attempt

  for attempt in {1..50}; do
    if ! kill -0 "${fixture_pid}" >/dev/null 2>&1; then
      echo "fixture exited before readiness; log: ${fixture_log}" >&2
      cat "${fixture_log}" >&2 || true
      return 1
    fi

    if curl --fail --silent --show-error --max-time 1 "${fixture_url}" >/dev/null; then
      return 0
    fi

    sleep 0.2
  done

  echo "fixture did not become ready at ${fixture_url}; log: ${fixture_log}" >&2
  cat "${fixture_log}" >&2 || true
  return 1
}

cd "${ROOT}"
cd vm/vagrant
vagrant validate
vagrant up --provider=virtualbox --provision
if ! vagrant ssh -c "ip -4 addr show | grep -q '192.168.56.10/24'" >/dev/null 2>&1; then
  vagrant reload --provision
fi

cd "${ROOT}"
go build -o "${fixture_bin}" ./vm/vagrant/fixture
"${fixture_bin}" -listen "${FIXTURE_ADDR}" >"${fixture_log}" 2>&1 &
fixture_pid=$!
wait_for_fixture

cd vm/vagrant
printf -v remote_cmd 'cd /home/vagrant/nie && sudo -E env NIE_VM_E2E=1 NIE_VM_FIXTURE_ADDR=%q NIE_VM_ALLOWED_HOST=%q ./vm/vagrant/run-tests.sh' "${FIXTURE_ADDR}" "${ALLOWED_HOST}"
vagrant ssh -c "${remote_cmd}"
