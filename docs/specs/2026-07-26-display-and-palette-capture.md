# Display and palette capture

Date: 2026-07-26
Status: implemented 2026-07-27, after three review rounds. Two items remain outstanding and
are deliberate: CI is still not pinned to a VICE at r46020 or later, so the live capture tests
skip there (the runner image's apt package predates the fix and building VICE from source is a
larger change); and the TraceRMI/Ghidra smoke test proving the ~140 KB base64 string survives
the real method transport is unwritten, since it belongs in `test/gui-smoke/run.sh` and needs a
Ghidra install plus Xvfb. Offline suite: 336 passing.

## Motivation

The connector exposes eighteen target methods covering registers, memory, checkpoints,
stepping and reset. It cannot see the screen.

For C64 work that is a capability gap, not an ergonomic one. The deliverable of a reversing
project is frequently a claim about what code *draws*. Memory reads confirm what bytes were
written; only the rendered frame confirms what they produced.

## Protocol facts

Verified against the VICE binary monitor documentation.

**`display get` — command `0x84`** (VICE 3.5, minimum API version 2)

Request body: `VC` (1 byte, use VIC-II; `0x00` selects VDC, ignored except on C128) and `FM`
(1 byte, format; only `0x00`, indexed 8-bit, is supported).

Response body:

| field | size | meaning |
| --- | --- | --- |
| `FL` | 4 | length of the metadata fields `DW`…`BP` — **excludes both `FL` and `BL`** |
| `DW` | 2 | debug width, uncropped |
| `DH` | 2 | debug height, uncropped |
| `XO` | 2 | X offset of the inner screen |
| `YO` | 2 | Y offset of the inner screen |
| `IW` | 2 | inner width |
| `IH` | 2 | inner height |
| `BP` | 1 | bits per pixel; 8 |
| `BL` | 4 | display buffer length |
| `BD` | `BL` | display buffer, one palette index per byte, row-major |

**No palette is included**; it comes from `palette get`.

**`palette get` — command `0x91`** (VICE 3.6, minimum API version 2)

Request body is one byte, `VC`. Response body is `PC` (2 bytes, item count) followed by `PC`
items of `IS` (1 byte, item size excluding itself), `RR`, `GG`, `BB`.

`protocol.py` already sends `API_VERSION = 0x02`, so the API-version floor is met.

## Blocking prerequisite: VICE builds before r46020 must not be sent `0x84`

VICE computed the `0x84` response length as `4 + info_length + buffer_length` while writing
`FL + info + BL + buffer`, which needs four more bytes. The consequence is a four-byte heap
overrun in the emulator and a response truncated by the final four pixels. Upstream fixed it
in **r46020** by changing the expression to `(4 + 4) + info_length + buffer_length`
(`monitor_binary_process_display_get()` in `src/monitor/monitor_binary.c`).

The fix postdates VICE 3.10, so the build installed on the development machine is affected.
This is not a validation problem to tolerate — the emulator performs the out-of-bounds write
*before* replying, so a client cannot make it safe after the fact.

Therefore the connector gates `0x84` on the build, using `VICE_INFO`. **The gate keys on
version first, because a release build reports no revision at all.** Measured on the
development machine: VICE 3.10 returns version `3.10.0.0` with `SV` = `0` (four bytes, all
zero). A revision-only rule would therefore refuse every release build, including the fixed
3.11 and later — the opposite of the intent.

The rule, with the revision authoritative whenever it exists:

1. if `SV != 0`, **require `SV >= 46020`** — a build that reports a revision is judged by it,
   so a contradictory `3.11.0.0 / r46019` is refused rather than admitted on its version;
2. otherwise (a release build, `SV == 0`), require the release family
   **`(major, minor) >= (3, 11)`**;
3. refuse anything unparseable.

Step 2 compares `(major, minor)` explicitly and nothing longer. The obvious-looking
`version_tuple > (3, 10)` is a trap: in Python `(3, 10, 0, 0) > (3, 10)` is `True`, which would
admit the vulnerable 3.10 release itself.

`SV` is decoded little-endian and `0` means "no revision", per the protocol's variable-length
version and revision fields.

**Ownership and cache lifecycle.** The check belongs immediately before
`ViceBmpClient.display_get()` may send `CMD_DISPLAY_GET`, not only in `capture_display`, so no
future caller can reach the command around it. The client holds an immutable VICE-info record —
version components plus `revision: Optional[int]` — cleared on every connect and every
termination. **Absent or unknown cached build information prevents `0x84`**; the guard never
falls open.

Two distinct failures, because they mean different things to a caller: a malformed or truncated
`VICE_INFO` is `vice_protocol_error`, while a well-formed response describing an unsupported
build is `vice_unsupported_build`, naming the detected version, the detected revision and the
requirement. Neither is `vice_invalid_argument`, which would read as a caller mistake.
- The strict `BL == delivered` check stays. On an affected build it would correctly reject the
  reply; padding or tolerating four missing pixels would conceal corruption.
- The live test and CI require a build at r46020 or later. The unpinned `apt install vice` in
  `.github/workflows/build.yml` does not establish that and must be pinned or built from
  source.

**The truncation is deliberately not reproduced locally, now or later.** Reproducing it means
sending `0x84` to a vulnerable build, which is the out-of-bounds write this section exists to
prevent. The upstream diff is the evidence; a positive live capture against r46020 or later is
the confirmation. Those two together are sufficient, and neither requires triggering the bug.

## Prerequisite: the monitor address form in the launcher

Found while attempting the live probe: on VICE 3.10, `-binarymonitoraddress 127.0.0.1:6512`
**binds nothing and reports no error**, while `-binarymonitoraddress ip4://127.0.0.1:6512`
binds and accepts connections immediately. Current VICE documentation uses the URI form.

`data/debugger-launchers/vice-c64-launch.sh` passes the bare `HOST:PORT` form. That must move to
the URI form, in the launcher and in CI, or live testing cannot start at all. This is
independent of the capture work and is worth fixing on its own.

## Contract

### protocol.py

Add `CMD_DISPLAY_GET = 0x84` / `RESP_DISPLAY_GET = 0x84` and `CMD_PALETTE_GET = 0x91` /
`RESP_PALETTE_GET = 0x91`, with body builders and parsers following the module's existing
little-endian struct conventions.

Display parsing, in this order:

1. read `FL`; require `FL >= 13`
2. read exactly `FL` bytes of metadata; parse the known 13-byte `DW`…`BP` prefix and **skip
   any remaining extension bytes**
3. read `BL`
4. read exactly `BL` bytes of `BD`
5. reject any trailing bytes

`FL` locates `BL`, not `BD`. Asserting `FL == 13` would defeat the forward compatibility that
using `FL` buys.

Validation, each error naming the offending value:

- `BP` must be `8`; the downstream pixel arithmetic assumes one byte per pixel
- `DW`, `DH`, `IW`, `IH` must all be positive
- `BL` must equal `DW * DH` when `BP == 8`; without a stride field no other length is
  renderable
- `XO + IW <= DW` and `YO + IH <= DH`
- palette `PC` must be `1`–`256`
- each palette item must have `IS >= 3`; parse RGB and skip the declared remainder, applying
  the same forward-compatible policy as `FL` rather than requiring exactly `3`
- no undeclared trailing bytes in either response

### Target method

One method, `capture_display`, declared in `src/main/py/src/vice/contracts.py` — the contract
source of truth, since `test_automation.py` enforces exact generation of the JSON — as
`c64_vice_v1_capture_display`, with capability `display.capture`, `SURFACE_REVISION = 2`, and
a regenerated `contracts/c64-vice-api-v1.json`.

| argument | required | notes |
| --- | --- | --- |
| `use_vic` | no | default `true`; must be an actual boolean, per existing validation conventions |
| `timeout_ms` | no | default `10000`; every automation operation is bounded |

Result:

```json
{
  "width": 384, "height": 272,
  "inner": {"x_offset": 32, "y_offset": 35, "width": 320, "height": 200},
  "bits_per_pixel": 8,
  "buffer_length": 104448,
  "buffer_base64": "…",
  "palette": [{"r": 0, "g": 0, "b": 0}, {"r": 255, "g": 255, "b": 255}],
  "vice_version": "3.11.0.0",
  "vice_revision": null
}
```

`vice_revision` is `null` on a supported **release** build, which reports no revision at all;
it carries the integer only for an SVN or nightly build. Both shapes are tested, since the
release case is the common one and an integer-only contract would misdescribe it.

- Pixels are **row-major, one byte per pixel, and the byte is an index into `palette` by
  array position**. Stated explicitly so no consumer has to infer it.
- `buffer_base64` is standard RFC 4648 base64 with padding. Roughly 104 KB raw becomes about
  139 KB encoded; the existing memory method already returns 65,536 bytes as 131,072 hex
  characters, so this is only modestly larger.
- `max(buffer)` must be less than `len(palette)`, checked in the combined capture. Otherwise
  the advertised result is not renderable and the failure belongs here, not downstream.
- **The connector returns the raw indexed buffer and the palette; it does not encode an
  image.** PNG encoding needs no emulator and is unit-testable upstream.

Rejected alternatives, recorded so they are not revisited: caller-specified output files
(paths refer to the connector host, may be unreachable from the caller, and add filesystem
mutation); streaming or chunked variants (disproportionate for occasional captures);
connector-side cropping (discards information the metadata describes and is trivial
upstream); and split display/palette public methods (the palette is tiny beside the frame, and
splitting invites stale pairing).

### Machine state: capture requires a stopped target

An earlier revision of this spec allowed capture while running, on the reasoning that reading a
frame changes nothing. That is wrong, and the mechanism is not subtle: **sending any
binary-monitor command traps VICE into the monitor**, which emits register information followed
by `STOPPED`. Upstream `monitor_check_binary()` calls `monitor_startup_trap()` whenever command
data is available.

This repository already depends on that behaviour — `acknowledge_interrupt()` implements
*interrupt* by sending `CMD_PING` with `mutating=True` and waiting for `stopped`. Sending a
command **is** how you stop the emulator here.

Confirmed empirically while probing: a client that sent `0x85` and then `0x91` received type
`0x31` (registers) and type `0x62` (`STOPPED`) first, both with request id `0xFFFFFFFF`, ahead
of the actual responses.

So a "capture while running" path would have produced exactly the state divergence the
controller exists to prevent: the frame request stops the emulator, the socket reader queues
`STOPPED`, the event coordinator cannot publish it because capture holds `operation_lock`, and
capture returns claiming the execution state is unchanged — after which the coordinator
publishes `STOPPED` and the state flips. A live assertion that the emulator "is still running
afterwards" would then pass or fail on scheduling alone.

`capture_display` therefore uses the existing `_stopped_call()`:

- reject `running` and `unknown` before sending any frame;
- share one timeout budget across display and palette inside the callback;
- increment `command_sequence` once;
- keep both protocol requests `mutating=False` — once the stopped precondition holds, they
  introduce no further state change.

A caller wanting a frame mid-execution performs `interrupt` → `capture_display` → `resume`
explicitly. Those mutations and their events stay visible, instead of hiding inside a method
advertised as read-only.

The display/palette pairing is still **not atomic** against an external palette-resource change;
the design minimizes the window rather than guaranteeing a consistent snapshot.

### Deliberately excluded

- **Cropping**, **VDC workflows beyond the `use_vic` pass-through**, and **frame streaming or
  diffing.** One capture per call; the metadata needed to crop is returned.

## Tests

Offline, with the existing `tests/bmp_helpers.py` fakes:

- Exact request-body bytes for both commands.
- Metadata parsing with `FL == 13`, and with `FL > 13` carrying unknown extension bytes
  **before `BL`**, asserting the buffer still lands correctly.
- Rejections, each asserting the message names the offending value: `FL < 13`, truncated
  metadata, `BP != 8`, `BL != DW * DH`, `BL` disagreeing with delivered bytes, zero
  dimensions, an inner rectangle exceeding the debug buffer, trailing bytes, palette count
  `0` or `> 256`, a truncated palette array, and palette coverage failure
  (`max(buffer) >= len(palette)`).
- `IS > 3` accepted with the extension skipped.
- Revision guard: version `3.10.0.0` with `SV` `0` refuses; version `3.11.0.0` with `SV` `0`
  proceeds and reports `vice_revision: null` (the release-build case a revision-only rule got
  wrong); version `3.10.0.0` with `SV` `46019` refuses and `46020` proceeds; **version
  `3.11.0.0` with `SV` `46019` refuses**, pinning that a present revision outranks the version;
  a malformed or truncated `VICE_INFO` raises `vice_protocol_error` rather than
  `vice_unsupported_build`; an unparseable version with `SV` `0` refuses. Each refusal asserts
  the code and that **no `0x84` frame was sent**.
- Guard placement and cache: a call reaching `display_get()` directly, bypassing
  `capture_display`, is still refused; the cached record is cleared on connect and on
  termination, and a cleared or absent record refuses rather than falling open.
- Controller: capture while `running` **fails and sends no protocol frame**, mirroring the
  existing read-guard test; capture while `unknown` likewise fails; capture while `stopped`
  succeeds, consumes one shared timeout budget, and increments `command_sequence` once.
- Unsolicited-event handling: a fake emitting registers and `STOPPED` with request id
  `0xFFFFFFFF` ahead of the real reply is demultiplexed correctly, so neither event is mistaken
  for a response.
- Automation: `buffer_base64` decodes back to the exact fake buffer.
- Contract: method, capability, `SURFACE_REVISION = 2`, regenerated JSON, `CHANGELOG.md`.

Live, only against a build at r46020 or later:

- Launch without `-warp`; assert the inner rectangle is 320×200, `len(buffer) == width *
  height`, the palette covers every index present, and at least two distinct indices appear —
  a uniformly blank frame passes every structural check while proving nothing.
- Capture attempted while the controller is actually running: expect `vice_target_not_stopped`,
  assert the controller is **still running** afterwards (the refusal must not have stopped it),
  then interrupt in `finally`. This replaces an earlier bullet asserting that a running capture
  succeeds, which described the design this spec reversed.
- One TraceRMI/Ghidra smoke test proving the ~140 KB string survives the real method
  transport; the current live suite only exercises Python-to-VICE.
