"""Stable names and operational limits for C64 VICE automation."""

API = "c64.vice/1"
API_MAJOR = 1
METHOD_NAMESPACE = "c64_vice_v1_"
CONNECTOR_NAME = "ghidra-vice-connector"
CONNECTOR_VERSION = "0.100.0"

LIMITS = {
    "keyboard_feed_bytes": 255,
    "memory_chunk_bytes": 16_384,
    "display_capture_chunk_bytes": 16_384,
}
