#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <verilog file or directory> [verilator options...]" >&2
  exit 1
fi

if ! command -v verilator >/dev/null 2>&1; then
  echo "Error: verilator is not installed or not in PATH." >&2
  exit 1
fi

target=$1
shift

if [ -d "$target" ]; then
  dir="$target"
else
  dir=$(dirname "$target")
fi

files=("$dir"/*.v)

echo "Compiling using Verilator: ${files[*]}"
verilator --cc "${files[@]}" -Wno-DECLFILENAME -Wno-PINNOCONNECT -Wno-fatal "$@"
