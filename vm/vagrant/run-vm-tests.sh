#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE_ADDR="${NIE_VM_FIXTURE_ADDR:-}"
FIXTURE_PORT="${NIE_VM_FIXTURE_PORT:-18080}"
ALLOWED_HOST="${NIE_VM_ALLOWED_HOST:-allowed.vm.test}"
GUEST_PRIVATE_IP="${NIE_VM_GUEST_PRIVATE_IP:-192.168.56.10}"
TMPDIR_ROOT="${TMPDIR:-/tmp}"

tmpdir="$(mktemp -d "${TMPDIR_ROOT}/nie-vm-tests.XXXXXX")"
fixture_bin="${tmpdir}/fixture"
fixture_log="${tmpdir}/fixture.log"

cleanup() {
  if [[ -n "${fixture_pid:-}" ]]; then
    kill "${fixture_pid}" >/dev/null 2>&1 || true
    wait "${fixture_pid}" 2>/dev/null || true
  fi
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

guest_has_private_ip() {
  vagrant ssh -c "ip -4 -o addr show to ${GUEST_PRIVATE_IP}/32" >/dev/null 2>&1
}

derive_fixture_addr() {
  local route_output host_ip

  if [[ -n "${FIXTURE_ADDR}" ]]; then
    return 0
  fi

  route_output="$(ip -4 route get "${GUEST_PRIVATE_IP}")"
  host_ip="$(awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}' <<<"${route_output}")"
  if [[ -z "${host_ip}" ]]; then
    echo "could not derive host fixture IP from route to ${GUEST_PRIVATE_IP}" >&2
    return 1
  fi

  FIXTURE_ADDR="${host_ip}:${FIXTURE_PORT}"
}

probe_fixture() {
  local fixture_host fixture_port status_line

  fixture_host="${FIXTURE_ADDR%:*}"
  fixture_port="${FIXTURE_ADDR##*:}"

  exec 3<>"/dev/tcp/${fixture_host}/${fixture_port}" || return 1
  printf 'GET /healthz HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "${fixture_host}" >&3
  IFS= read -r -t 1 status_line <&3 || {
    exec 3<&-
    exec 3>&-
    return 1
  }
  exec 3<&-
  exec 3>&-

  [[ "${status_line}" == *" 200 "* ]]
}

wait_for_fixture() {
  local attempt

  for attempt in {1..50}; do
    if ! kill -0 "${fixture_pid}" >/dev/null 2>&1; then
      echo "fixture exited before readiness; log: ${fixture_log}" >&2
      cat "${fixture_log}" >&2 || true
      return 1
    fi

    if probe_fixture >/dev/null 2>&1; then
      return 0
    fi

    sleep 0.2
  done

  echo "fixture did not become ready at ${FIXTURE_ADDR}; log: ${fixture_log}" >&2
  cat "${fixture_log}" >&2 || true
  return 1
}

cd "${ROOT}"
cd vm/vagrant
vagrant validate
vagrant up --provider=virtualbox --provision
if ! guest_has_private_ip; then
  vagrant reload --provision
fi
guest_has_private_ip

cd "${ROOT}"
derive_fixture_addr

go build -o "${fixture_bin}" ./vm/vagrant/fixture
"${fixture_bin}" -listen "${FIXTURE_ADDR}" >"${fixture_log}" 2>&1 &
fixture_pid=$!
wait_for_fixture

cd vm/vagrant
printf -v remote_cmd 'cd /home/vagrant/nie && sudo -E env NIE_VM_E2E=1 NIE_VM_FIXTURE_ADDR=%q NIE_VM_ALLOWED_HOST=%q ./vm/vagrant/run-tests.sh' "${FIXTURE_ADDR}" "${ALLOWED_HOST}"
vagrant ssh -c "${remote_cmd}"
