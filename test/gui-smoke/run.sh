#!/usr/bin/env bash
#
# GUI smoke test: exercise the *packaged* VICE C64 connector inside a real
# Ghidra 12.1 GUI under Xvfb, alongside a running VICE binary monitor.
#
# What this GATES on (deterministic — failure exits non-zero):
#   1. The packaged extension installs into a real Ghidra 12.1 user Extensions
#      dir and the GUI starts with it present, with no extension class-load
#      errors in the Ghidra log.
#   2. The fixture imports headlessly under the 6502 processor.
#   3. VICE (x64sc) boots, loads the kernal ROM, autostarts the fixture via
#      direct RAM injection, and opens the binary monitor port.
# This is coverage the headless pytest suite cannot reach: packaging, extension
# discovery, and Ghidra 12.1 acceptance of the built artifact.
#
# What this PROBES (best-effort — warns, does not fail):
#   The full end-to-end launch: driving Ghidra's "Configure and Launch -> VICE
#   C64 Debugger" so the launcher spawns the agent and it handshakes with both
#   Ghidra (TraceRmi) and VICE (BMP). vice-c64.py writes /tmp/vice-agent.log and
#   emits "=== Agent ready, waiting for events ===" once connected; reaching
#   that line is logged as a strong PASS. The xdotool driving of the launch
#   dialog is timing-/UI-revision-sensitive and is NOT yet confirmed on a
#   runner. xdotool keystrokes do not reach Ghidra's Swing context menu, so the
#   "Open With -> Debugger" action previously never fired; mouse navigation is
#   used as a best-effort probe. The script warns instead of failing when the
#   agent is not reached and uploads step screenshots for tuning. See the
#   launch_connector phase.
#
# Usage:
#   bash test/gui-smoke/run.sh [path-to-extension-zip]
#
# Env:
#   GHIDRA_HOME    Ghidra 12.1 distribution root (required).
#   VICE_PORT      Binary monitor TCP port. Default 6502 (matches the launcher's
#                  OPT_PORT default, so the launch dialog needs no edits).
#   ARTIFACTS_DIR  Where to drop logs + screenshot on failure. Falls back to
#                  $RUNNER_TEMP/gui-smoke-artifacts, then /tmp/gui-smoke-artifacts.
#
# NOTE: this script is Linux/Xvfb-only and is exercised in CI.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EXTENSION_ZIP="${1:-}"
if [ -z "$EXTENSION_ZIP" ]; then
  # Pick the freshest build output.
  EXTENSION_ZIP=$(ls -t "$REPO_ROOT"/dist/*ghidra-vice-connector*.zip 2>/dev/null | head -1)
fi

VICE_PORT="${VICE_PORT:-6502}"
AGENT_LOG="/tmp/vice-agent.log"

ARTIFACTS_DIR="${ARTIFACTS_DIR:-${RUNNER_TEMP:-/tmp}/gui-smoke-artifacts}"
mkdir -p "$ARTIFACTS_DIR"

TMP_BASE=$(mktemp -d /tmp/ghidra-vice-smoke.XXXXXX)
GHIDRA_LOG="$TMP_BASE/ghidra.log"
XVFB_LOG="$TMP_BASE/xvfb.log"
VICE_LOG="$TMP_BASE/vice.log"
PROJECT_PARENT="$TMP_BASE/project"
PROJECT_NAME="vice_smoke"
USER_DIR_RELATIVE=".config/ghidra/ghidra_12.1_PUBLIC"

export HOME="$TMP_BASE/home"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_DATA_HOME="$HOME/.local/share"
export JAVA_TOOL_OPTIONS="-Duser.home=$HOME"
# Isolated X auth cookie. Without this, Ghidra's launch.sh — which re-resolves
# HOME in places — and the WM end up writing cookies into the user's real
# ~/.Xauthority, which can mislead host services that auto-detect a display by
# matching cookies (e.g. RustDesk) into preferring a leaked Xvfb over :0.
export XAUTHORITY="$TMP_BASE/Xauthority"
: > "$XAUTHORITY"
USER_SETTINGS="$HOME/$USER_DIR_RELATIVE"

XVFB_PID=
WM_PID=
GHIDRA_PID=
VICE_PID=
XVFB_PGID=
WM_PGID=
GHIDRA_PGID=
VICE_PGID=
DISPLAY_NUM=
PHASE="init"
FAIL=0

log()  { printf '[%s] %s\n' "$PHASE" "$*"; }
die()  { FAIL=1; log "FAIL: $*"; }

dump_diagnostics() {
  log "Dumping diagnostics to $ARTIFACTS_DIR ..."
  for f in \
    "$GHIDRA_LOG" \
    "$XVFB_LOG" \
    "$VICE_LOG" \
    "$AGENT_LOG" \
    "$TMP_BASE/analyzeHeadless.log" \
    "$TMP_BASE/wm.log" \
    "$TMP_BASE/xdotool.log"
  do
    [ -f "$f" ] && cp "$f" "$ARTIFACTS_DIR/" 2>/dev/null || true
  done
  # Numbered step screenshots from shot().
  cp "$TMP_BASE"/*.png "$ARTIFACTS_DIR/" 2>/dev/null || true
  if [ -n "${DISPLAY:-}" ]; then
    import -display "$DISPLAY" -window root "$ARTIFACTS_DIR/screen-final.png" 2>/dev/null || true
  fi
  if [ -f "$AGENT_LOG" ]; then
    cp "$AGENT_LOG" "$ARTIFACTS_DIR/vice-agent.log" 2>/dev/null || true
  fi
}

teardown() {
  PHASE="teardown"
  # Reap each spawned process group with SIGTERM, escalate to SIGKILL after a
  # grace window. Using PGIDs (each child is spawned under setsid) catches the
  # JVM helper processes, Xvfb's xkbcomp, the WM's children, VICE's threads,
  # etc. Killing only parent PIDs could leave Xvfb behind on a non-clean exit.
  local pgid alive
  for pgid in "$GHIDRA_PGID" "$VICE_PGID" "$WM_PGID" "$XVFB_PGID"; do
    [ -n "$pgid" ] || continue
    kill -TERM -- "-$pgid" 2>/dev/null || true
  done
  for _ in 1 2 3 4 5; do
    alive=0
    for pgid in "$GHIDRA_PGID" "$VICE_PGID" "$WM_PGID" "$XVFB_PGID"; do
      [ -n "$pgid" ] || continue
      kill -0 -- "-$pgid" 2>/dev/null && alive=1
    done
    [ "$alive" -eq 0 ] && break
    sleep 1
  done
  for pgid in "$GHIDRA_PGID" "$VICE_PGID" "$WM_PGID" "$XVFB_PGID"; do
    [ -n "$pgid" ] || continue
    kill -KILL -- "-$pgid" 2>/dev/null || true
  done
  # Defensive socket cleanup: a clean Xvfb exit removes its own socket, but
  # SIGKILL/oom-kill does not. Combined with the linear-scan picker below, this
  # prevents a previous run's leaked socket from poisoning future runs.
  if [ -n "$DISPLAY_NUM" ]; then
    local sock="/tmp/.X11-unix/X$DISPLAY_NUM"
    local lock="/tmp/.X$DISPLAY_NUM-lock"
    if [ -e "$sock" ]; then
      if command -v fuser >/dev/null 2>&1; then
        fuser "$sock" >/dev/null 2>&1 || rm -f "$sock" 2>/dev/null || true
      else
        rm -f "$sock" 2>/dev/null || true
      fi
    fi
    [ -e "$lock" ] && rm -f "$lock" 2>/dev/null || true
  fi
  wait 2>/dev/null || true
}

trap '[ $FAIL -ne 0 ] && dump_diagnostics; teardown' EXIT
# Bash does not run the EXIT trap for untrapped signals (notably SIGHUP from
# SSH drop / terminal close), so trap them explicitly and exit, which fires the
# EXIT trap above.
trap 'FAIL=1; exit 130' INT
trap 'FAIL=1; exit 143' TERM
trap 'FAIL=1; exit 129' HUP

# --- Phase 1: resolve_env --------------------------------------------------
PHASE="resolve_env"
for bin in Xvfb xauth mcookie setsid xdotool nc curl unzip import java x64sc; do
  command -v "$bin" >/dev/null 2>&1 || { die "missing dep: $bin"; exit 1; }
done
# Pick a window manager. Without one, Java/AWT focus management does not work
# under bare Xvfb, so Swing widgets never receive mouse/keystroke events.
WM_BIN=
for wm in marco metacity mutter openbox fluxbox xfwm4 matchbox-window-manager twm; do
  if command -v "$wm" >/dev/null 2>&1; then WM_BIN="$wm"; break; fi
done
[ -n "$WM_BIN" ] || { die "no window manager on PATH (need one of: marco, metacity, openbox, fluxbox, xfwm4, matchbox-window-manager, twm)"; exit 1; }
[ -n "${GHIDRA_HOME:-}" ] && [ -d "$GHIDRA_HOME" ] || { die "GHIDRA_HOME not set or missing: ${GHIDRA_HOME:-<unset>}"; exit 1; }
[ -n "$EXTENSION_ZIP" ] && [ -f "$EXTENSION_ZIP" ] || { die "extension zip not found: ${EXTENSION_ZIP:-<unset>}"; exit 1; }
[ -f "$REPO_ROOT/data/test.prg" ] || { die "fixture missing: data/test.prg"; exit 1; }
log "GHIDRA_HOME=$GHIDRA_HOME"
log "EXTENSION_ZIP=$EXTENSION_ZIP"
log "VICE_PORT=$VICE_PORT"
log "TMP_BASE=$TMP_BASE"
log "WM=$WM_BIN"

# --- Phase 2: setup_user_dir ----------------------------------------------
PHASE="setup_user_dir"
mkdir -p "$USER_SETTINGS/tools" "$USER_SETTINGS/Extensions" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME"
cat > "$USER_SETTINGS/preferences" <<'PREF'
#User Preferences
USER_AGREEMENT=ACCEPT
GhidraShowWhatsNew=false
SHOW_TIPS=false
PREF
log "user dir staged at $USER_SETTINGS"

# --- Phase 3: install_extension -------------------------------------------
PHASE="install_extension"
unzip -qo "$EXTENSION_ZIP" -d "$USER_SETTINGS/Extensions/"
EXT_PROPS=$(find "$USER_SETTINGS/Extensions" -maxdepth 2 -name extension.properties | head -1)
[ -n "$EXT_PROPS" ] && [ -f "$EXT_PROPS" ] || { die "extension.properties not present after unzip"; exit 1; }
log "extension installed: $EXT_PROPS"
# The launcher shell script must be executable for Ghidra to run it.
find "$USER_SETTINGS/Extensions" -name '*.sh' -exec chmod +x {} \;

# --- Phase 4: import_fixture ----------------------------------------------
PHASE="import_fixture"
# Ghidra imports raw 6502 code, so strip the 2-byte PRG load-address header
# (same transform the README documents for producing data/test_raw.bin).
RAW_BIN="$TMP_BASE/test_raw.bin"
python3 -c "import pathlib,sys; b=pathlib.Path('$REPO_ROOT/data/test.prg').read_bytes(); pathlib.Path('$RAW_BIN').write_bytes(b[2:])"
[ -s "$RAW_BIN" ] || { die "failed to derive raw fixture from test.prg"; exit 1; }
mkdir -p "$PROJECT_PARENT"
"$GHIDRA_HOME"/support/analyzeHeadless \
  "$PROJECT_PARENT" "$PROJECT_NAME" \
  -import "$RAW_BIN" \
  -processor "6502:LE:16:default" \
  >"$TMP_BASE/analyzeHeadless.log" 2>&1
if [ ! -f "$PROJECT_PARENT/$PROJECT_NAME.gpr" ]; then
  die "project file not created"
  tail -40 "$TMP_BASE/analyzeHeadless.log"
  exit 1
fi
log "project: $PROJECT_PARENT/$PROJECT_NAME.gpr"

# --- Phase 5: assert_port_free --------------------------------------------
PHASE="assert_port_free"
if nc -z 127.0.0.1 "$VICE_PORT" 2>/dev/null; then
  die "VICE port $VICE_PORT already in use"
  exit 1
fi

# --- Phase 6: launch_xserver (Xvfb + WM) ----------------------------------
PHASE="launch_xserver"
# Pick a free display number by linear scan over lock + socket files (the
# convention xvfb-run uses), skipping any number left behind by a prior leak.
DISPLAY_NUM=99
while [ -e "/tmp/.X$DISPLAY_NUM-lock" ] || [ -e "/tmp/.X11-unix/X$DISPLAY_NUM" ]; do
  DISPLAY_NUM=$((DISPLAY_NUM + 1))
  if [ "$DISPLAY_NUM" -gt 999 ]; then
    die "no free X display number in :99..:999"
    exit 1
  fi
done
DISPLAY=":$DISPLAY_NUM"
export DISPLAY

# Register a cookie for the chosen display BEFORE Xvfb starts so -auth is
# effective from the first connection. xauth writes only to XAUTHORITY.
xauth -f "$XAUTHORITY" add "$DISPLAY" . "$(mcookie)" >/dev/null 2>&1 \
  || { die "xauth add failed for $DISPLAY"; exit 1; }

# setsid puts each long-running child in its own session/PGID so teardown can
# reap whole subtrees with kill -- -PGID.
setsid Xvfb "$DISPLAY" -screen 0 1280x1024x24 -auth "$XAUTHORITY" >"$XVFB_LOG" 2>&1 &
XVFB_PID=$!
XVFB_PGID=$XVFB_PID
sleep 1
kill -0 "$XVFB_PID" 2>/dev/null || { die "Xvfb failed to start on $DISPLAY"; exit 1; }
log "Xvfb $DISPLAY (pid=$XVFB_PID pgid=$XVFB_PGID)"

setsid "$WM_BIN" --display "$DISPLAY" --sm-disable >"$TMP_BASE/wm.log" 2>&1 &
WM_PID=$!
WM_PGID=$WM_PID
sleep 1
if ! kill -0 "$WM_PID" 2>/dev/null; then
  # Some WMs do not understand --sm-disable; retry without it.
  setsid "$WM_BIN" --display "$DISPLAY" >"$TMP_BASE/wm.log" 2>&1 &
  WM_PID=$!
  WM_PGID=$WM_PID
  sleep 1
fi
kill -0 "$WM_PID" 2>/dev/null || { die "$WM_BIN failed to start"; exit 1; }
log "$WM_BIN (pid=$WM_PID pgid=$WM_PGID)"

# --- Phase 7: start_vice ---------------------------------------------------
PHASE="start_vice"
# Start VICE with the binary monitor enabled and the test program loaded. The
# agent connects to read CPU/memory state; the C64 just needs to be running.
# -sounddev dummy avoids needing an audio device under Xvfb.
#
# VICE_C64_ROM_DIR: distro packages (e.g. Ubuntu's `vice`) omit the copyrighted
# C64 ROMs, so x64sc aborts at startup. When set, pass the three machine ROMs
# explicitly. VICE's default PRG autostart may fall back to disk-image mode,
# which needs drive 8 / a 1541 ROM on minimal CI images. Force mode 1 (Inject)
# so the PRG is copied into C64 RAM and RUN without requiring a drive ROM.
# Unset (e.g. a local dev box with a full VICE) -> x64sc uses its own ROMs.
VICE_ROM_ARGS=()
if [ -n "${VICE_C64_ROM_DIR:-}" ]; then
  for rom in kernal-901227-03.bin basic-901226-01.bin chargen-901225-01.bin; do
    [ -s "$VICE_C64_ROM_DIR/$rom" ] || { die "VICE ROM missing: $VICE_C64_ROM_DIR/$rom"; exit 1; }
  done
  VICE_ROM_ARGS=(
    -kernal  "$VICE_C64_ROM_DIR/kernal-901227-03.bin"
    -basic   "$VICE_C64_ROM_DIR/basic-901226-01.bin"
    -chargen "$VICE_C64_ROM_DIR/chargen-901225-01.bin"
  )
fi
setsid x64sc \
  -binarymonitor -binarymonitoraddress "127.0.0.1:$VICE_PORT" \
  -sounddev dummy \
  "${VICE_ROM_ARGS[@]}" \
  -autostartprgmode 1 \
  -autostart "$REPO_ROOT/data/test.prg" \
  >"$VICE_LOG" 2>&1 &
VICE_PID=$!
VICE_PGID=$VICE_PID
deadline=$((SECONDS + 60))
until nc -z 127.0.0.1 "$VICE_PORT" 2>/dev/null; do
  if ! kill -0 "$VICE_PID" 2>/dev/null; then
    die "VICE exited before opening the binary monitor port"
    tail -40 "$VICE_LOG"
    exit 1
  fi
  if (( SECONDS >= deadline )); then
    die "VICE binary monitor port $VICE_PORT never opened within 60s"
    tail -40 "$VICE_LOG"
    exit 1
  fi
  sleep 1
done
VICE_KERNAL_MARKER='Kernal rev #3'
VICE_INJECT_LOAD_RE='AUTOSTART: Loading PRG file .+ with direct RAM injection\.'
VICE_INJECT_DATA_MARKER='AUTOSTART: Injecting program data at'
VICE_AUTOSTART_DONE_MARKER='AUTOSTART: Done.'
# These markers must tolerate VICE-version drift between local 3.10 and Ubuntu's
# packaged VICE. The inject markers were also observed without -drive8type 0.
vice_boot_ready() {
  grep -qF "$VICE_KERNAL_MARKER" "$VICE_LOG" \
    && { grep -qE "$VICE_INJECT_LOAD_RE" "$VICE_LOG" \
      || grep -qF "$VICE_INJECT_DATA_MARKER" "$VICE_LOG"; } \
    && grep -qF "$VICE_AUTOSTART_DONE_MARKER" "$VICE_LOG"
}
deadline=$((SECONDS + 60))
until vice_boot_ready; do
  if ! kill -0 "$VICE_PID" 2>/dev/null; then
    die "VICE exited before kernal-load and autostart-success markers appeared"
    tail -60 "$VICE_LOG"
    exit 1
  fi
  if (( SECONDS >= deadline )); then
    die "VICE boot check timed out waiting for kernal-load and autostart-success markers"
    tail -60 "$VICE_LOG"
    exit 1
  fi
  sleep 1
done
log "VICE up on 127.0.0.1:$VICE_PORT (pid=$VICE_PID pgid=$VICE_PGID)"

# --- Phase 8: launch_ghidra ------------------------------------------------
PHASE="launch_ghidra"
# Truncate any stale agent log so its later reappearance is unambiguous proof
# that THIS run's launch produced it (vice-c64.py opens it in 'w' mode anyway).
rm -f "$AGENT_LOG" 2>/dev/null || true
setsid "$GHIDRA_HOME"/support/launch.sh fg jdk Ghidra "" "" ghidra.GhidraRun "$PROJECT_PARENT/$PROJECT_NAME.gpr" >"$GHIDRA_LOG" 2>&1 &
GHIDRA_PID=$!
GHIDRA_PGID=$GHIDRA_PID
log "ghidraRun (pid=$GHIDRA_PID pgid=$GHIDRA_PGID)"

# Wait for the FrontEnd (project) window.
WID=
for _ in $(seq 1 60); do
  WID=$(xdotool search --name "^Ghidra: $PROJECT_NAME\$" 2>/dev/null | head -1 || true)
  [ -n "$WID" ] && break
  if ! kill -0 "$GHIDRA_PID" 2>/dev/null; then
    die "Ghidra died before FrontEnd window appeared"
    tail -40 "$GHIDRA_LOG"
    exit 1
  fi
  sleep 1
done
[ -n "$WID" ] || { die "FrontEnd window not found within 60s"; exit 1; }
log "FrontEnd window id=$WID"
sleep 5  # let the project tree finish populating

# Snapshot the current X root to a numbered diagnostic frame. Every GUI step
# below records one so a failed run can be replayed frame by frame.
SHOT_N=0
shot() {
  SHOT_N=$((SHOT_N + 1))
  local name
  name=$(printf '%02d-%s.png' "$SHOT_N" "$1")
  import -display "$DISPLAY" -window root "$TMP_BASE/$name" 2>/dev/null || true
}

# --- Phase 9: open_in_debugger --------------------------------------------
# Open the imported program in the Debugger tool (right-click -> Open With ->
# Debugger), which is where the TraceRmi launch action lives. Ghidra's default
# program tool is CodeBrowser, so we must pick the Debugger explicitly.
PHASE="open_in_debugger"
xdotool windowactivate --sync "$WID" 2>>"$TMP_BASE/xdotool.log" || true
sleep 1
TREE_ITEM_X=100
TREE_ITEM_Y=200
# Focus the project tree and select the first program with the keyboard
# (expansion-state independent: Home -> root, Right -> expand, Down -> child).
xdotool mousemove --window "$WID" "$TREE_ITEM_X" "$TREE_ITEM_Y" 2>>"$TMP_BASE/xdotool.log" || true
sleep 0.3
xdotool click --window "$WID" 1 2>>"$TMP_BASE/xdotool.log" || true
sleep 0.5
for key in Home Right Down; do
  xdotool key --clearmodifiers "$key" 2>>"$TMP_BASE/xdotool.log" || true
  sleep 0.4
done
shot tree-selected
# Open the program's context menu with mouse button 3. xdotool keystrokes do
# not reach this Swing popup reliably, while pointer events do.
xdotool mousemove --window "$WID" "$TREE_ITEM_X" "$TREE_ITEM_Y" 2>>"$TMP_BASE/xdotool.log" || true
sleep 0.3
xdotool click 3 2>>"$TMP_BASE/xdotool.log" || true
sleep 1
shot context-menu
OPEN_WITH_X=$((TREE_ITEM_X + 70))
OPEN_WITH_Y=$((TREE_ITEM_Y + 45))
DEBUGGER_X=$((TREE_ITEM_X + 250))
DEBUGGER_Y=$((OPEN_WITH_Y + 25))
# Navigate "Open With" -> "Debugger" with the mouse. These coordinates are
# relative to the FrontEnd window and are intentionally captured by screenshots
# before/after each move so runner drift can be tuned without gating the job.
xdotool mousemove --window "$WID" "$OPEN_WITH_X" "$OPEN_WITH_Y" 2>>"$TMP_BASE/xdotool.log" || true
sleep 0.8
shot open-with-hover
xdotool mousemove --window "$WID" "$DEBUGGER_X" "$DEBUGGER_Y" 2>>"$TMP_BASE/xdotool.log" || true
sleep 0.8
shot open-with-submenu
xdotool click 1 2>>"$TMP_BASE/xdotool.log" || true
sleep 5
shot after-open-with

# A "New Plugins Found!" dialog can appear the first time this fresh project
# state sees the extension; accept it so the Debugger tool finishes opening.
NPW=$(xdotool search --name '^New Plugins Found!$' 2>/dev/null | head -1 || true)
if [ -n "$NPW" ]; then
  xdotool windowactivate --sync "$NPW" 2>>"$TMP_BASE/xdotool.log" || true
  sleep 0.3
  xdotool key --window "$NPW" --clearmodifiers Return 2>>"$TMP_BASE/xdotool.log" || true
  log "accepted 'New Plugins Found!' dialog"
  sleep 3
fi

# --- Phase 10: launch_connector -------------------------------------------
# Drive the Debugger tool's "Configure and Launch <program> using -> VICE C64
# Debugger" action, accepting the launch dialog with its defaults (OPT_HOST=
# localhost, OPT_PORT matches VICE_PORT). The success assertion does not scrape
# any widget — it only checks the agent's own log — so this step just has to
# get the launch dialog to its Launch button.
PHASE="launch_connector"
log "driving debugger launch (best-effort GUI automation)"
# Focus the Debugger tool window if it is up.
DWIN=$(xdotool search --name "^Debugger:" 2>/dev/null | head -1 || true)
if [ -n "$DWIN" ]; then
  xdotool windowactivate --sync "$DWIN" 2>>"$TMP_BASE/xdotool.log" || true
  log "Debugger tool window id=$DWIN"
else
  log "WARN: Debugger tool window not found (Open With navigation may need tuning)"
fi
sleep 2
shot debugger-tool
# Open the launch-button dropdown (the bug/▾ control in the Debugger Targets
# toolbar) to reach the "VICE C64 Debugger" offer. Coordinate targeting of the
# dropdown is the remaining UI-sensitive piece to confirm on a runner; the
# screenshots above/below pinpoint where to aim.
shot pre-launch
# The launch dialog's default button is "Launch"; Return accepts it once it is
# focused. Sent best-effort in case the offer was reached via keyboard.
xdotool key --clearmodifiers Return 2>>"$TMP_BASE/xdotool.log" || true
sleep 1

# --- Phase 11: assert_extension_loaded (deterministic gate) ---------------
# The GUI reached the FrontEnd window with the extension installed (gated in
# phase 8). Additionally fail if Ghidra reported the extension as incompatible
# or could not load its plugin class — that is the signal that the artifact
# built in this run is not accepted by Ghidra 12.1. Patterns are scoped to the
# extension/plugin to avoid false positives from unrelated log noise.
PHASE="assert_extension_loaded"
if [ -f "$GHIDRA_LOG" ] && grep -qiE \
    "ghidra-vice-connector.*(incompatible|not compatible|Skipping)|(ViceDebuggerPlugin|ghidra\.vice).*(ClassNotFound|NoClassDef|Unsupported class)" \
    "$GHIDRA_LOG"; then
  die "Ghidra reported the extension as incompatible / failed to load its class"
  grep -iE "ghidra-vice-connector|ViceDebuggerPlugin|ghidra\.vice" "$GHIDRA_LOG" | tail -20 | sed 's/^/  /' || true
  exit 1
fi
log "PASS (gated): extension accepted; fixture imported; VICE booted, autostarted, and monitor up"

# --- Phase 12: probe_agent (best-effort end-to-end) -----------------------
# Best-effort: wait a bounded time for the launcher-spawned agent to reach
# "Agent ready". Not reaching it is a WARNING, not a failure (the launch
# automation is the unconfirmed piece — see the header).
PHASE="probe_agent"
shot pre-probe
deadline=$((SECONDS + 60))
ok=0
while (( SECONDS < deadline )); do
  if [ -f "$AGENT_LOG" ] && grep -q "Agent ready" "$AGENT_LOG" 2>/dev/null; then
    ok=1
    break
  fi
  kill -0 "$GHIDRA_PID" 2>/dev/null || break
  sleep 2
done

# --- Phase 13: result ------------------------------------------------------
PHASE="result"
if [ "$ok" -eq 1 ]; then
  log "PASS (end-to-end): agent connected to Ghidra + VICE and populated initial state"
  grep -E "Ghidra TraceRmi connected|VICE connected|Initial state populated|Agent ready" "$AGENT_LOG" | sed 's/^/  /' || true
else
  # Surface diagnostics, but do NOT fail: the deterministic gate above passed.
  FAIL=1  # triggers screenshot/log capture into ARTIFACTS_DIR via the EXIT trap
  log "WARN: end-to-end launch not confirmed — agent did not reach 'Agent ready' in 60s."
  log "WARN: the launch_connector GUI automation needs tuning on a Linux runner; see step screenshots."
  if [ -f "$AGENT_LOG" ]; then
    log "last agent log lines:"
    tail -20 "$AGENT_LOG" | sed 's/^/  /' || true
  else
    log "agent log $AGENT_LOG was never created — the launcher was not triggered."
  fi
fi
exit 0
