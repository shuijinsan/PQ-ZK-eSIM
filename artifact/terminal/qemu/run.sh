#!/bin/bash
set -euo pipefail

command -v qemu-aarch64-static >/dev/null 2>&1 || {
  echo "qemu-aarch64-static is missing; install qemu-user-static"
  exit 1
}

exec qemu-aarch64-static -L /usr/aarch64-linux-gnu "$@"
