"""Unit tests for pwndbg-mcp.

Pure-logic tests run without GDB. The integration test runs only if `gdb` is
available on PATH (skipped otherwise), so the suite is CI-friendly.

MIT License - Copyright (c) 2025-present pwndbg-mcp contributors
"""

import shutil

import pytest

from pwndbg_mcp.gdb_controller import GdbController, strip_ansi
from pwndbg_mcp.snapshot import text_to_png


class _Bare(GdbController):
    """Construct without spawning gdb (for testing the pure helpers)."""

    def __init__(self):
        self._sent = "@@PWNDBGMCP_EOC_test@@"
        self.last_raw = b""
        self.master_fd = None
        self.proc = None


# --------------------------------------------------------------- strip_ansi
class TestStripAnsi:
    def test_removes_color_codes(self):
        assert strip_ansi(b"\x1b[31mRED\x1b[0m") == "RED"

    def test_removes_carriage_returns(self):
        assert "\r" not in strip_ansi(b"a\r\nb")

    def test_plain_passthrough(self):
        assert strip_ansi(b"hello world") == "hello world"


# --------------------------------------------------------------- _clean
class TestClean:
    def setup_method(self):
        self.c = _Bare()

    def test_cuts_at_sentinel(self):
        raw = "real output\n" + self.c._sent + "\npwndbg> "
        assert self.c._clean(raw, "regs") == "real output"

    def test_strips_trailing_prompt(self):
        raw = "Breakpoint 1 at 0x1803\npwndbg> \n" + self.c._sent
        assert self.c._clean(raw, "break main") == "Breakpoint 1 at 0x1803"

    def test_empty_when_only_prompt(self):
        raw = "pwndbg> \n" + self.c._sent
        assert self.c._clean(raw, "set $rdi=1") == ""

    def test_drops_leading_echoed_command(self):
        raw = "telescope $rsp\n00:0000 data\n" + self.c._sent
        cleaned = self.c._clean(raw, "telescope $rsp")
        assert cleaned.startswith("00:0000")


# --------------------------------------------------------------- snapshot
class TestSnapshot:
    def test_png_signature(self):
        png = text_to_png("Canary = 0xdeadbeef\nRIP 0x401000", "context")
        assert png[:8] == b"\x89PNG\r\n\x1a\n"

    def test_handles_empty(self):
        png = text_to_png("", "")
        assert png[:8] == b"\x89PNG\r\n\x1a\n"


# --------------------------------------------------------------- hex decode
class TestHexDecode:
    def test_spaces_and_newlines(self):
        h = "41 42\n43 44"
        assert bytes.fromhex(h.replace(" ", "").replace("\n", "")) == b"ABCD"


# --------------------------------------------------------------- integration
@pytest.mark.skipif(shutil.which("gdb") is None, reason="gdb not installed")
class TestIntegration:
    def test_session_runs_basic_command(self):
        g = GdbController()
        try:
            assert g.is_alive()
            out = g.cmd("print 1+1")
            assert "2" in out
        finally:
            g.shutdown()
