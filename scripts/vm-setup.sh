#!/usr/bin/env bash
# Creates or starts the zaun Lima VM, then builds and tests in it.
# Remove: limactl delete -f zaun
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
command -v limactl >/dev/null || brew install lima

if limactl list -q 2>/dev/null | grep -qx zaun; then
  limactl start zaun || true  # already running is fine
else
  cfg="$(mktemp -t zaun-lima).yaml"
  cat >"$cfg" <<EOF
vmType: vz
cpus: 4
memory: 4GiB
disk: 30GiB
images:
  - location: https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img
    arch: aarch64
  - location: https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img
    arch: x86_64
mounts:
  - location: "$repo"
    writable: true
provision:
  - mode: system
    script: |
      #!/bin/bash
      set -eux
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y clang cmake ninja-build pkg-config libseccomp-dev hyperfine
      # Dev/CI only.
      echo kernel.apparmor_restrict_unprivileged_userns=0 >/etc/sysctl.d/60-zaun.conf
      sysctl --system
EOF
  limactl start --name=zaun --tty=false "$cfg"
  rm -f "$cfg"
fi

limactl shell --workdir "$repo" zaun bash -c '
  set -e
  uname -srm
  cmake -S . -B build-vm -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug
  cmake --build build-vm
  ctest --test-dir build-vm --output-on-failure
'
echo "VM ready. Shell in with: limactl shell --workdir \"$repo\" zaun"
