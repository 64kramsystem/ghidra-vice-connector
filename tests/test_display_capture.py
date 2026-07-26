"""Display and palette capture: protocol, build guard, controller, automation.

Everything here is offline. The build guard exists because VICE before r46020
overruns its own allocation while answering `display get` (0x84), so no test may
send that command to a real emulator; the fakes below are `MockViceServer`, which
is not one.
"""

import base64
import contextlib
import json
import struct
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from vice import automation, commands, contracts
from vice.controller import ViceController, ViceStateError
from vice.protocol import (
    CMD_DISPLAY_GET,
    CMD_PALETTE_GET,
    CMD_VICE_INFO,
    DISPLAY_GET_MIN_RELEASE,
    DISPLAY_GET_MIN_REVISION,
    RESP_DISPLAY_GET,
    RESP_PALETTE_GET,
    RESP_REGISTERS_GET,
    RESP_STOPPED,
    RESP_VICE_INFO,
    DisplayFrame,
    PaletteEntry,
    ViceBmpClient,
    ViceInfo,
    ViceProtocolError,
    ViceUnsupportedBuildError,
    ViceValidationError,
    build_display_get_body,
    build_palette_get_body,
    parse_display_get,
    parse_palette_get,
    parse_vice_info,
)

from .bmp_helpers import (
    DEFAULT_DISPLAY_BUFFER,
    DEFAULT_PALETTE,
    MockViceServer,
    build_display_response,
    build_palette_response,
    build_vice_info_body,
)
from .test_controller import FakeClient


SUPPORTED_RELEASE = (3, 11, 0, 0)
VULNERABLE_RELEASE = (3, 10, 0, 0)


# ── Fixtures and helpers ──────────────────────────────────────────────────────

@contextlib.contextmanager
def bmp_client(
    *,
    version=SUPPORTED_RELEASE,
    revision: int = 0,
    display_body=None,
    palette_body=None,
    read_vice_info: bool = True,
    before_display=None,
):
    """A real `ViceBmpClient` over a socket to a fake speaking BMP.

    `requests` records the request payloads the fake actually received, so a
    refusal can assert that *no* 0x84 frame reached the wire.
    """
    server = MockViceServer()
    requests = {"display": [], "palette": []}
    server.handle(
        CMD_VICE_INFO,
        lambda _: (RESP_VICE_INFO, build_vice_info_body(version, revision)),
    )

    def display(payload):
        requests["display"].append(payload)
        if before_display is not None:
            before_display(server)
        return (
            RESP_DISPLAY_GET,
            build_display_response() if display_body is None else display_body,
        )

    def palette(payload):
        requests["palette"].append(payload)
        return (
            RESP_PALETTE_GET,
            build_palette_response() if palette_body is None else palette_body,
        )

    server.handle(CMD_DISPLAY_GET, display)
    server.handle(CMD_PALETTE_GET, palette)
    server.start()
    client = ViceBmpClient("127.0.0.1", server.port)
    try:
        client.connect()
        if read_vice_info:
            client.vice_info()
        yield client, requests, server
    finally:
        client.disconnect()
        server.stop()


def guarded_client(version, revision):
    """A client with a planted build record and a command recorder.

    No socket: the point is whether `display_get()` reaches `command()` at all.
    """
    client = ViceBmpClient()
    client._vice_info = (
        None if version is None else ViceInfo(tuple(version), revision)
    )
    client.command = MagicMock(
        return_value=MagicMock(body=build_display_response())
    )
    return client


class DisplayFakeClient(FakeClient):
    """`FakeClient` plus recorded display/palette capture calls."""

    def __init__(self, frame=None, palette=None):
        super().__init__()
        self.frame = frame or DisplayFrame(4, 2, 1, 0, 2, 2, 8,
                                           DEFAULT_DISPLAY_BUFFER)
        self.palette = palette or [PaletteEntry(*item)
                                   for item in DEFAULT_PALETTE]
        self.display_calls = []
        self.palette_calls = []

    def display_get(self, use_vic=True, *, timeout_ms):
        self.display_calls.append((use_vic, timeout_ms))
        time.sleep(0.02)
        return self.frame

    def palette_get(self, use_vic=True, *, timeout_ms):
        self.palette_calls.append((use_vic, timeout_ms))
        return self.palette


def capture_controller(client=None):
    client = client or DisplayFakeClient()
    controller = ViceController(client)
    controller.connect(discover_registers=False)
    controller.start_event_coordinator(assume_stopped=True)
    return client, controller


@pytest.fixture
def automation_controller():
    value = MagicMock()
    value.instance_id = "12345678-1234-1234-1234-123456789abc"
    value.command_sequence = 7
    value.vice_version = "3.11.0.0"
    value.vice_revision = None
    value.status.return_value = {
        "connection_state": "connected",
        "execution_state": "stopped",
        "event_sequence": 0,
    }
    commands.STATE.controller = value
    yield value
    commands.STATE.controller = None


def process():
    value = automation.C64()
    value.path = commands.C64_PATH
    return value


def payload(text):
    return json.loads(text)


# ── Request bodies ────────────────────────────────────────────────────────────

class TestRequestBodies:
    def test_display_get_body_is_vc_then_fm(self):
        assert build_display_get_body(True) == b"\x01\x00"
        assert build_display_get_body(False) == b"\x00\x00"

    def test_palette_get_body_is_one_vc_byte(self):
        assert build_palette_get_body(True) == b"\x01"
        assert build_palette_get_body(False) == b"\x00"

    def test_display_get_sends_exactly_those_bytes(self):
        with bmp_client() as (client, requests, _server):
            client.display_get(True)
            client.display_get(False)
        assert requests["display"] == [b"\x01\x00", b"\x00\x00"]

    def test_palette_get_sends_exactly_those_bytes(self):
        with bmp_client() as (client, requests, _server):
            client.palette_get(True)
            client.palette_get(False)
        assert requests["palette"] == [b"\x01", b"\x00"]

    def test_use_vic_must_be_a_boolean(self):
        client = guarded_client(SUPPORTED_RELEASE, 0)
        with pytest.raises(ViceValidationError, match="use_vic"):
            client.display_get(1)
        client.command.assert_not_called()


# ── Display metadata parsing ──────────────────────────────────────────────────

class TestDisplayParsing:
    def test_parses_the_13_byte_metadata_prefix(self):
        frame = parse_display_get(build_display_response())
        assert frame == DisplayFrame(4, 2, 1, 0, 2, 2, 8,
                                     DEFAULT_DISPLAY_BUFFER)

    def test_declared_metadata_length_is_exactly_13_by_default(self):
        body = build_display_response()
        assert struct.unpack_from("<I", body, 0)[0] == 13

    def test_unknown_metadata_extension_precedes_the_buffer_length(self):
        """`FL` locates `BL`, not `BD`; extension bytes must be skipped."""
        body = build_display_response(info_extension=b"\xAA\xBB\xCC\xDD")
        assert struct.unpack_from("<I", body, 0)[0] == 17
        frame = parse_display_get(body)
        assert frame.width == 4
        assert frame.bits_per_pixel == 8
        assert frame.buffer == DEFAULT_DISPLAY_BUFFER

    def test_rejects_metadata_length_below_13(self):
        body = struct.pack("<I", 12) + bytes(12) + struct.pack("<I", 0)
        with pytest.raises(ViceProtocolError, match="12"):
            parse_display_get(body)

    def test_rejects_truncated_metadata(self):
        body = build_display_response()[:10]
        with pytest.raises(ViceProtocolError, match="display get"):
            parse_display_get(body)

    def test_rejects_bits_per_pixel_other_than_8(self):
        body = build_display_response(bits_per_pixel=4)
        with pytest.raises(ViceProtocolError, match="4"):
            parse_display_get(body)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("width", 0),
            ("height", 0),
            ("inner_width", 0),
            ("inner_height", 0),
        ],
    )
    def test_rejects_non_positive_dimensions(self, field, value):
        body = build_display_response(
            **{field: value}, declared_buffer_length=8
        )
        with pytest.raises(ViceProtocolError, match=field.replace("_", " ")):
            parse_display_get(body)

    def test_rejects_buffer_length_that_is_not_width_times_height(self):
        body = build_display_response(
            declared_buffer_length=9, buffer=bytes(9)
        )
        with pytest.raises(ViceProtocolError, match="9"):
            parse_display_get(body)

    def test_rejects_buffer_length_disagreeing_with_delivered_bytes(self):
        body = build_display_response(
            buffer=DEFAULT_DISPLAY_BUFFER[:6], declared_buffer_length=8
        )
        with pytest.raises(ViceProtocolError, match="only 6"):
            parse_display_get(body)

    def test_rejects_inner_rectangle_wider_than_the_debug_buffer(self):
        body = build_display_response(x_offset=3, inner_width=2)
        with pytest.raises(ViceProtocolError, match="inner screen"):
            parse_display_get(body)

    def test_rejects_inner_rectangle_taller_than_the_debug_buffer(self):
        body = build_display_response(y_offset=1, inner_height=2)
        with pytest.raises(ViceProtocolError, match="inner screen"):
            parse_display_get(body)

    def test_rejects_trailing_bytes(self):
        body = build_display_response(trailing=b"\x00\x00")
        with pytest.raises(ViceProtocolError, match="trailing"):
            parse_display_get(body)


# ── Palette parsing ───────────────────────────────────────────────────────────

class TestPaletteParsing:
    def test_parses_rgb_items(self):
        entries = parse_palette_get(build_palette_response())
        assert entries == [PaletteEntry(0, 0, 0), PaletteEntry(255, 255, 255)]

    def test_accepts_and_skips_a_longer_item(self):
        entries = parse_palette_get(
            build_palette_response(item_extension=b"\x7F\x7F")
        )
        assert entries == [PaletteEntry(0, 0, 0), PaletteEntry(255, 255, 255)]

    def test_rejects_item_size_below_3(self):
        body = struct.pack("<H", 1) + struct.pack("<BBB", 2, 1, 2)
        with pytest.raises(ViceProtocolError, match="2"):
            parse_palette_get(body)

    def test_rejects_zero_items(self):
        with pytest.raises(ViceProtocolError, match="0"):
            parse_palette_get(build_palette_response(entries=()))

    def test_rejects_more_than_256_items(self):
        body = build_palette_response(
            entries=tuple((0, 0, 0) for _ in range(257))
        )
        with pytest.raises(ViceProtocolError, match="257"):
            parse_palette_get(body)

    def test_rejects_a_truncated_item_array(self):
        with pytest.raises(ViceProtocolError, match="palette"):
            parse_palette_get(build_palette_response(truncate=2))

    def test_rejects_trailing_bytes(self):
        with pytest.raises(ViceProtocolError, match="trailing"):
            parse_palette_get(build_palette_response(trailing=b"\x00"))


# ── VICE_INFO parsing ─────────────────────────────────────────────────────────

class TestViceInfoParsing:
    def test_returns_every_version_component_and_the_revision(self):
        info = parse_vice_info(build_vice_info_body((3, 11, 0, 0), 46021))
        assert info.version == (3, 11, 0, 0)
        assert info.revision == 46021
        assert info.version_string == "3.11.0.0"

    def test_release_build_reports_no_revision(self):
        info = parse_vice_info(build_vice_info_body((3, 10, 0, 0), 0))
        assert info.revision is None
        assert info.version_string == "3.10.0.0"

    def test_absent_svn_field_reports_no_revision(self):
        info = parse_vice_info(bytes([4, 3, 11, 0, 0]) + b"\x00")
        assert info.revision is None

    @pytest.mark.parametrize(
        "body",
        [
            b"",
            bytes([2, 3, 11]) + b"\x00",          # fewer than 3 components
            bytes([4, 3, 11, 0, 0]) + b"\x04\x00",  # truncated SVN field
            bytes([4, 3, 11, 0, 0]) + b"\x00\x99",  # undeclared trailing byte
        ],
    )
    def test_malformed_info_is_a_protocol_error(self, body):
        with pytest.raises(ViceProtocolError):
            parse_vice_info(body)


# ── The build guard ───────────────────────────────────────────────────────────

class TestBuildGuard:
    def test_minimums_match_the_upstream_fix(self):
        assert DISPLAY_GET_MIN_REVISION == 46020
        assert DISPLAY_GET_MIN_RELEASE == (3, 11)

    @pytest.mark.parametrize(
        ("version", "revision"),
        [
            (VULNERABLE_RELEASE, None),   # the vulnerable release itself
            ((3, 9, 0, 0), None),
            (VULNERABLE_RELEASE, 46019),  # revision below the fix
            # A present revision outranks the version: this build claims 3.11
            # but its revision predates the fix, so it is refused.
            (SUPPORTED_RELEASE, 46019),
            ((3,), None),                 # unparseable version, no revision
            ((), None),
        ],
    )
    def test_unsupported_builds_are_refused_without_sending_0x84(
        self, version, revision
    ):
        client = guarded_client(version, revision)
        with pytest.raises(ViceUnsupportedBuildError) as caught:
            client.display_get()
        assert caught.value.code == "vice_unsupported_build"
        client.command.assert_not_called()

    def test_refusal_names_the_detected_build_and_the_requirement(self):
        client = guarded_client(VULNERABLE_RELEASE, None)
        with pytest.raises(ViceUnsupportedBuildError) as caught:
            client.display_get()
        message = str(caught.value)
        assert "3.10.0.0" in message
        assert "46020" in message or "3.11" in message

    @pytest.mark.parametrize(
        ("version", "revision"),
        [
            (SUPPORTED_RELEASE, None),        # release build, no revision
            ((3, 12, 0, 0), None),
            (VULNERABLE_RELEASE, 46020),      # fixed nightly on a 3.10 base
            (VULNERABLE_RELEASE, 46021),
        ],
    )
    def test_supported_builds_proceed(self, version, revision):
        client = guarded_client(version, revision)
        client.display_get()
        assert client.command.call_count == 1
        assert client.command.call_args.args[0] == CMD_DISPLAY_GET

    def test_absent_build_record_refuses_rather_than_falling_open(self):
        client = guarded_client(None, None)
        with pytest.raises(ViceUnsupportedBuildError, match="unknown"):
            client.display_get()
        client.command.assert_not_called()

    def test_guard_sits_in_display_get_so_it_cannot_be_reached_around(self):
        """`capture_display` is not the only door; this one is also locked."""
        with bmp_client(version=VULNERABLE_RELEASE) as (client, requests, _s):
            with pytest.raises(ViceUnsupportedBuildError):
                client.display_get()
        assert requests["display"] == []

    def test_a_supported_build_reaches_the_socket(self):
        with bmp_client(version=SUPPORTED_RELEASE) as (client, requests, _s):
            frame = client.display_get()
        assert requests["display"] == [b"\x01\x00"]
        assert frame.buffer == DEFAULT_DISPLAY_BUFFER

    def test_record_is_absent_until_vice_info_is_read(self):
        with bmp_client(read_vice_info=False) as (client, requests, _s):
            assert client.vice_build_info is None
            with pytest.raises(ViceUnsupportedBuildError):
                client.display_get()
            assert client.vice_info().version == SUPPORTED_RELEASE
            assert client.vice_build_info is not None
            client.display_get()
        assert requests["display"] == [b"\x01\x00"]

    def test_record_is_cleared_on_termination(self):
        with bmp_client() as (client, _requests, _server):
            assert client.vice_build_info is not None
            client.disconnect()
            assert client.vice_build_info is None

    @pytest.mark.parametrize(
        ("version", "revision", "expected_version", "expected_revision"),
        [
            # The release case a revision-only rule got wrong: supported, and
            # it has no revision to report.
            (SUPPORTED_RELEASE, 0, "3.11.0.0", None),
            (VULNERABLE_RELEASE, 46021, "3.10.0.0", 46021),
        ],
    )
    def test_connection_publishes_the_version_and_the_revision(
        self, version, revision, expected_version, expected_revision
    ):
        server = MockViceServer()
        server.handle(
            CMD_VICE_INFO,
            lambda _: (RESP_VICE_INFO, build_vice_info_body(version, revision)),
        )
        server.start()
        controller = ViceController(ViceBmpClient("127.0.0.1", server.port))
        try:
            controller.connect(discover_registers=False)
            assert controller.vice_version == expected_version
            assert controller.vice_revision == expected_revision
        finally:
            controller.close()
            server.stop()

    def test_record_is_cleared_on_connect(self):
        server = MockViceServer()
        server.start()
        client = ViceBmpClient("127.0.0.1", server.port)
        # A record left over from an earlier session must not survive into a
        # new connection, which may be a different emulator entirely.
        client._vice_info = ViceInfo(SUPPORTED_RELEASE, None)
        try:
            client.connect(discover_registers=False)
            assert client.vice_build_info is None
        finally:
            client.disconnect()
            server.stop()


# ── Demultiplexing the monitor trap ───────────────────────────────────────────

class TestUnsolicitedFramesDuringCapture:
    def test_registers_and_stopped_events_are_not_mistaken_for_responses(self):
        """Any binary-monitor command traps VICE into the monitor first.

        The trap emits registers (0x31) and STOPPED (0x62) with request id
        0xFFFFFFFF ahead of the real 0x84 reply.
        """
        def trap(server):
            server.send_event(RESP_REGISTERS_GET, struct.pack("<H", 0))
            server.send_event(RESP_STOPPED, struct.pack("<H", 0xC000))

        events = []
        with bmp_client(before_display=trap) as (client, _requests, _server):
            client.set_event_callback(events.append)
            frame = client.display_get()
            palette = client.palette_get()
            deadline = time.monotonic() + 1
            while not events and time.monotonic() < deadline:
                time.sleep(0.005)
            assert client.connected
            diagnostics = [item.response_type for item in client.diagnostics]
        assert frame.buffer == DEFAULT_DISPLAY_BUFFER
        assert len(palette) == 2
        assert [event.kind for event in events] == ["stopped"]
        assert events[0].pc == 0xC000
        assert RESP_REGISTERS_GET in diagnostics


# ── Controller ────────────────────────────────────────────────────────────────

class TestControllerCapture:
    def test_capture_while_running_sends_no_protocol_frame(self):
        client, controller = capture_controller()
        with controller._condition:
            controller._execution_state = "running"
        with pytest.raises(ViceStateError) as caught:
            controller.capture_display()
        assert caught.value.code == "vice_target_not_stopped"
        assert client.display_calls == []
        assert client.palette_calls == []
        controller.close()

    def test_capture_while_unknown_sends_no_protocol_frame(self):
        client, controller = capture_controller()
        with controller._condition:
            controller._execution_state = "unknown"
        with pytest.raises(ViceStateError):
            controller.capture_display()
        assert client.display_calls == []
        assert client.palette_calls == []
        controller.close()

    def test_capture_while_stopped_shares_one_timeout_budget(self):
        client, controller = capture_controller()
        before = controller.command_sequence
        sequence, (frame, palette) = controller.capture_display(
            timeout_ms=500
        )
        assert sequence == before + 1
        assert controller.command_sequence == before + 1
        assert frame.buffer == DEFAULT_DISPLAY_BUFFER
        assert palette == [PaletteEntry(*item) for item in DEFAULT_PALETTE]
        display_budget = client.display_calls[0][1]
        palette_budget = client.palette_calls[0][1]
        assert 1 <= palette_budget < display_budget <= 500
        controller.close()

    def test_use_vic_is_passed_through_to_both_requests(self):
        client, controller = capture_controller()
        controller.capture_display(use_vic=False, timeout_ms=500)
        assert client.display_calls[0][0] is False
        assert client.palette_calls[0][0] is False
        controller.close()

    def test_rejects_a_buffer_index_the_palette_does_not_cover(self):
        client = DisplayFakeClient(
            frame=DisplayFrame(4, 2, 1, 0, 2, 2, 8, bytes([0, 1, 2, 3,
                                                           0, 1, 2, 3])),
        )
        client, controller = capture_controller(client)
        with pytest.raises(ViceProtocolError, match="3"):
            controller.capture_display(timeout_ms=500)
        controller.close()


# ── Automation surface ────────────────────────────────────────────────────────

class TestCaptureDisplayMethod:
    def test_result_shape_and_base64_round_trip(self, automation_controller):
        frame = DisplayFrame(384, 272, 32, 35, 320, 200, 8,
                             bytes(range(256)) * 408)
        palette = [PaletteEntry(index, index, index) for index in range(256)]
        automation_controller.capture_display.return_value = (
            11, (frame, palette)
        )
        result = payload(automation.capture_display(process(), True, 1000))
        assert result["ok"] is True
        assert result["command_sequence"] == 11
        body = result["result"]
        assert body["width"] == 384
        assert body["height"] == 272
        assert body["inner"] == {
            "x_offset": 32, "y_offset": 35, "width": 320, "height": 200,
        }
        assert body["bits_per_pixel"] == 8
        assert body["buffer_length"] == len(frame.buffer)
        assert base64.b64decode(body["buffer_base64"]) == frame.buffer
        assert body["palette"][1] == {"r": 1, "g": 1, "b": 1}
        assert len(body["palette"]) == 256
        assert body["vice_version"] == "3.11.0.0"
        assert body["vice_revision"] is None
        automation_controller.capture_display.assert_called_once_with(
            use_vic=True, timeout_ms=1000
        )

    def test_base64_is_rfc4648_with_padding(self, automation_controller):
        frame = DisplayFrame(2, 1, 0, 0, 2, 1, 8, b"\x00\x01")
        automation_controller.capture_display.return_value = (
            11, (frame, [PaletteEntry(0, 0, 0), PaletteEntry(1, 1, 1)])
        )
        result = payload(automation.capture_display(process(), True, 1000))
        assert result["result"]["buffer_base64"] == "AAE="

    def test_svn_build_reports_an_integer_revision(self, automation_controller):
        automation_controller.vice_revision = 46021
        frame = DisplayFrame(2, 1, 0, 0, 2, 1, 8, b"\x00\x00")
        automation_controller.capture_display.return_value = (
            11, (frame, [PaletteEntry(0, 0, 0)])
        )
        result = payload(automation.capture_display(process(), True, 1000))
        assert result["result"]["vice_revision"] == 46021

    def test_unsupported_build_becomes_a_stable_error_envelope(
        self, automation_controller
    ):
        automation_controller.capture_display.side_effect = (
            ViceUnsupportedBuildError("VICE 3.10.0.0 predates r46020")
        )
        result = payload(automation.capture_display(process(), True, 1000))
        assert result["ok"] is False
        assert result["error"]["code"] == "vice_unsupported_build"
        assert result["error"]["command"] == "capture_display"

    def test_use_vic_must_be_a_boolean(self, automation_controller):
        result = payload(automation.capture_display(process(), 1, 1000))
        assert result["ok"] is False
        assert result["error"]["code"] == "vice_invalid_argument"
        automation_controller.capture_display.assert_not_called()


# ── Contract ──────────────────────────────────────────────────────────────────

class TestContract:
    def test_capture_display_is_declared(self):
        names = [item["name"] for item in contracts.METHODS]
        assert "c64_vice_v1_capture_display" in names
        declared = next(
            item for item in contracts.METHODS
            if item["name"] == "c64_vice_v1_capture_display"
        )
        assert declared["parameters"] == [
            {"name": "process", "type": "C64", "required": True},
            {"name": "use_vic", "type": "BOOL", "required": False,
             "default": True},
            {"name": "timeout_ms", "type": "LONG", "required": False,
             "default": 10_000},
        ]

    def test_capability_and_surface_revision(self):
        assert "display.capture" in contracts.CAPABILITIES
        assert contracts.SURFACE_REVISION == 2
        assert "display.capture" in contracts.build_contract()["capabilities"]

    def test_changelog_records_the_capability(self):
        text = Path(__file__).resolve().parents[1].joinpath(
            "CHANGELOG.md"
        ).read_text(encoding="utf-8")
        unreleased = text.split("## Unreleased", 1)[1].split("\n## ", 1)[0]
        assert "capture_display" in unreleased
