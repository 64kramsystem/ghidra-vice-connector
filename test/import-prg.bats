#!/usr/bin/env bats
# Tests for data/support/import-prg.sh, driving the real script against a stub
# analyzeHeadless that records its argv and captures the imported raw file
# (the helper deletes its temp dir on exit, so the stub must copy it).

setup() {
  REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
  HELPER="$REPO_ROOT/data/support/import-prg.sh"
  export CAPTURE_DIR="$BATS_TEST_TMPDIR/capture"
  mkdir -p "$CAPTURE_DIR"
  export GHIDRA_HOME="$BATS_TEST_TMPDIR/ghidra"
  mkdir -p "$GHIDRA_HOME/support"
  cat > "$GHIDRA_HOME/support/analyzeHeadless" <<'EOS'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$CAPTURE_DIR/argv"
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  if [[ ${args[i]} == -import ]]; then
    cp "${args[i + 1]}" "$CAPTURE_DIR/raw.bin"
  fi
done
EOS
  chmod +x "$GHIDRA_HOME/support/analyzeHeadless"
}

@test "imports at the load address from the PRG header" {
  run "$HELPER" "$REPO_ROOT/data/test.prg" "$BATS_TEST_TMPDIR/proj" demo
  [ "$status" -eq 0 ]
  grep -qxF -- '-loader-baseAddr' "$CAPTURE_DIR/argv"
  grep -qxF -- '0x801' "$CAPTURE_DIR/argv"
}

@test "passes processor, cspec, loader and overwrite" {
  run "$HELPER" "$REPO_ROOT/data/test.prg" "$BATS_TEST_TMPDIR/proj" demo
  [ "$status" -eq 0 ]
  grep -qxF -- '6502:LE:16:default' "$CAPTURE_DIR/argv"
  grep -qxF -- 'BinaryLoader' "$CAPTURE_DIR/argv"
  grep -qxF -- '-overwrite' "$CAPTURE_DIR/argv"
  grep -qxF -- 'default' "$CAPTURE_DIR/argv"
}

@test "passes the project dir and name" {
  run "$HELPER" "$REPO_ROOT/data/test.prg" "$BATS_TEST_TMPDIR/proj" demo
  [ "$status" -eq 0 ]
  head -2 "$CAPTURE_DIR/argv" | grep -qxF "$BATS_TEST_TMPDIR/proj"
  head -2 "$CAPTURE_DIR/argv" | grep -qxF 'demo'
}

@test "strips exactly the 2-byte header" {
  run "$HELPER" "$REPO_ROOT/data/test.prg" "$BATS_TEST_TMPDIR/proj" demo
  [ "$status" -eq 0 ]
  tail -c +3 "$REPO_ROOT/data/test.prg" > "$BATS_TEST_TMPDIR/expected.bin"
  cmp "$CAPTURE_DIR/raw.bin" "$BATS_TEST_TMPDIR/expected.bin"
}

@test "names the program <base>_raw.bin" {
  run "$HELPER" "$REPO_ROOT/data/test.prg" "$BATS_TEST_TMPDIR/proj" demo
  [ "$status" -eq 0 ]
  import_path=$(grep -A1 -xF -- '-import' "$CAPTURE_DIR/argv" | tail -1)
  [ "$(basename "$import_path")" = 'test_raw.bin' ]
}

@test "honors a non-0801 load address" {
  printf '\x00\xc0\xea\xea\xea' > "$BATS_TEST_TMPDIR/c000.prg"
  run "$HELPER" "$BATS_TEST_TMPDIR/c000.prg" "$BATS_TEST_TMPDIR/proj" demo
  [ "$status" -eq 0 ]
  grep -qxF -- '0xc000' "$CAPTURE_DIR/argv"
}

@test "fails without GHIDRA_HOME" {
  unset GHIDRA_HOME
  run "$HELPER" "$REPO_ROOT/data/test.prg" "$BATS_TEST_TMPDIR/proj" demo
  [ "$status" -ne 0 ]
  [[ $output == *GHIDRA_HOME* ]]
}

@test "fails when analyzeHeadless is missing" {
  rm "$GHIDRA_HOME/support/analyzeHeadless"
  run "$HELPER" "$REPO_ROOT/data/test.prg" "$BATS_TEST_TMPDIR/proj" demo
  [ "$status" -ne 0 ]
  [[ $output == *analyzeHeadless* ]]
}

@test "fails on a missing PRG file" {
  run "$HELPER" "$BATS_TEST_TMPDIR/nope.prg" "$BATS_TEST_TMPDIR/proj" demo
  [ "$status" -ne 0 ]
  [[ $output == *'not found'* ]]
}

@test "fails on a too-short PRG file" {
  printf '\x01\x08' > "$BATS_TEST_TMPDIR/short.prg"
  run "$HELPER" "$BATS_TEST_TMPDIR/short.prg" "$BATS_TEST_TMPDIR/proj" demo
  [ "$status" -ne 0 ]
  [[ $output == *'too short'* ]]
}
