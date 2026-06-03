#!/usr/bin/env bash

set -o pipefail
set -o errexit
set -o nounset
set -o errtrace
shopt -s inherit_errexit

c_help="Usage: GHIDRA_HOME=/path/to/ghidra $(basename "$0") [-h|--help] <prg-file> <project-dir> <project-name>

Imports a C64 PRG into a Ghidra project at the load address stored in the PRG's 2-byte header, so no manual header stripping or post-import rebase is needed.

The imported program is named <prg-basename>_raw.bin."

v_prg_file=
v_project_dir=
v_project_name=

function decode_cmdline_args {
  local params
  params=$(getopt --options h --long help --name "$(basename "$0")" -- "$@")

  eval set -- "$params"

  while true; do
    case $1 in
      -h|--help)
        echo "$c_help"
        exit 0 ;;
      --)
        shift
        break ;;
    esac
  done

  if [[ $# -ne 3 ]]; then
    echo "$c_help"
    exit 1
  fi

  v_prg_file=$1
  v_project_dir=$2
  v_project_name=$3
}

function check_preconditions {
  if [[ -z ${GHIDRA_HOME:-} || ! -x ${GHIDRA_HOME:-}/support/analyzeHeadless ]]; then
    echo "GHIDRA_HOME must point to a Ghidra install (support/analyzeHeadless not found)" >&2
    exit 1
  fi
  if [[ ! -f $v_prg_file ]]; then
    echo "PRG file not found: $v_prg_file" >&2
    exit 1
  fi
  if [[ $(wc -c < "$v_prg_file") -lt 3 ]]; then
    echo "PRG file too short (needs a 2-byte load address plus data): $v_prg_file" >&2
    exit 1
  fi
}

function main {
  check_preconditions

  local lo hi load_addr
  lo=$(od -An -tu1 -j0 -N1 "$v_prg_file" | tr -d ' ')
  hi=$(od -An -tu1 -j1 -N1 "$v_prg_file" | tr -d ' ')
  load_addr=$((hi * 256 + lo))

  local tmp_dir raw_file
  tmp_dir=$(mktemp -d)
  # shellcheck disable=SC2064  # expand now: tmp_dir is local to main
  trap "rm -rf '$tmp_dir'" EXIT
  raw_file="$tmp_dir/$(basename "${v_prg_file%.prg}")_raw.bin"
  tail -c +3 "$v_prg_file" > "$raw_file"

  printf 'Importing %s at load address $%04X\n' "$v_prg_file" "$load_addr"

  "$GHIDRA_HOME/support/analyzeHeadless" "$v_project_dir" "$v_project_name" \
    -import "$raw_file" \
    -processor "6502:LE:16:default" \
    -cspec default \
    -loader BinaryLoader \
    -loader-baseAddr "$(printf '0x%x' "$load_addr")" \
    -overwrite
}

decode_cmdline_args "$@"
main
