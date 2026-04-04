#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

GO_VERSION="1.24.2"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TARBALL}"

apt-get update
apt-get install -y \
  build-essential \
  ca-certificates \
  clang \
  curl \
  git \
  iproute2 \
  libbpf-dev \
  libelf-dev \
  llvm \
  linux-libc-dev \
  make \
  nftables \
  pkg-config

multiarch_include_dir="/usr/include/$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
if [ ! -e /usr/include/asm ] && [ -d "${multiarch_include_dir}/asm" ]; then
  ln -s "${multiarch_include_dir}/asm" /usr/include/asm
fi

need_go_install=1
if command -v go >/dev/null 2>&1; then
  current_go_version="$(go env GOVERSION 2>/dev/null || true)"
  if [ "${current_go_version}" = "go${GO_VERSION}" ]; then
    need_go_install=0
  fi
fi

if [ "${need_go_install}" -eq 1 ]; then
  curl -fsSL "${GO_URL}" -o "/tmp/${GO_TARBALL}"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"
fi

ln -sf /usr/local/go/bin/go /usr/local/bin/go
cat >/etc/profile.d/go-path.sh <<'EOF'
export PATH="/usr/local/go/bin:${PATH}"
EOF
