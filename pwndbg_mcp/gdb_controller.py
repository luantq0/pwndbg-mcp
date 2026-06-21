"""PTY-based GDB/pwndbg controller.

We talk to the real gdb CLI through a pseudo-terminal so pwndbg renders its
full output (telescope, context, vmmap, regs, ...). Command completion is
detected with an echoed sentinel, which is robust against pwndbg overriding
the prompt. The inferior shares the PTY, so the agent can also feed stdin to
the debugged process (send_to_process) and read its output.
"""

from __future__ import annotations

import os
import pty
import re
import select
import signal
import struct
import subprocess
import termios
import time
import uuid

# ANSI CSI/escape sequences, plus readline's prompt-ignore markers (\x01/\x02)
# that pwndbg embeds around its colored prompt, plus bare CR.
ANSI_RE = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[=>]|\x0f|[\x01\x02]|\r")

# pwndbg pads section rules (U+2500 '─', U+2550 '═') to the full terminal width.
# With a wide PTY that is hundreds of tokens per command of pure noise, so we
# collapse those runs. NOTE: telescope arrows use U+2014 '—' (not U+2500), so
# they are left intact.
_RULE_RUN = re.compile(r"[─═]{3,}")
_RULE_ONLY = re.compile(r"^[─═\s]+$")


def strip_ansi(data: bytes) -> str:
    return ANSI_RE.sub(b"", data).decode("utf-8", "replace")


def compact(text: str) -> str:
    """Strip token-wasting decoration from pwndbg output while keeping content.

    - collapse long '─'/'═' rule runs to '──'
    - drop pure-rule lines and the LEGEND banner
    - squeeze 3+ blank lines down to one
    """
    out = []
    blanks = 0
    for ln in text.split("\n"):
        if ln.startswith("LEGEND:"):
            continue
        if _RULE_ONLY.match(ln):
            continue
        ln = _RULE_RUN.sub("──", ln).rstrip()
        if not ln.strip():
            blanks += 1
            if blanks > 1:
                continue
        else:
            blanks = 0
        out.append(ln)
    return "\n".join(out).strip("\n")


class GdbError(RuntimeError):
    pass


class GdbController:
    """A persistent gdb+pwndbg session behind a PTY."""

    def __init__(self, gdb: str = "gdb"):
        self.gdb = gdb
        self.master_fd: int | None = None
        self.proc: subprocess.Popen | None = None
        self._sent = "@@PWNDBGMCP_EOC_" + uuid.uuid4().hex[:8] + "@@"
        # last raw (ANSI-preserving) capture, used for image snapshots
        self.last_raw: bytes = b""
        self.start()

    # ----------------------------------------------------------------- lifecycle
    def start(self) -> str:
        master, slave = pty.openpty()
        # wide window => pwndbg won't wrap or paginate
        try:
            import fcntl

            ws = struct.pack("HHHH", 100, 1000, 0, 0)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, ws)
        except Exception:
            pass
        # Disable terminal echo so our typed commands (and the echoed sentinel)
        # do NOT come back in the output stream and cause premature matches.
        try:
            attrs = termios.tcgetattr(slave)
            attrs[3] = attrs[3] & ~(termios.ECHO | termios.ECHOE
                                    | termios.ECHOK | termios.ECHONL)
            termios.tcsetattr(slave, termios.TCSANOW, attrs)
        except Exception:
            pass
        self.proc = subprocess.Popen(
            [
                self.gdb,
                "-q",
                "-ex", "set editing off",
                "-ex", "set pagination off",
                "-ex", "set confirm off",
                "-ex", "set width 0",
                "-ex", "set height 0",
                "-ex", "set disassembly-flavor intel",
            ],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            preexec_fn=os.setsid,
            close_fds=True,
        )
        os.close(slave)
        self.master_fd = master
        banner = self._read_until(self._sent_or_prompt(), timeout=30, idle=2.0,
                                  prime=True)
        return banner

    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def shutdown(self):
        try:
            if self.master_fd is not None:
                os.write(self.master_fd, b"\nquit\n")
                time.sleep(0.2)
        except Exception:
            pass
        try:
            if self.proc and self.proc.poll() is None:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        except Exception:
            pass
        try:
            if self.master_fd is not None:
                os.close(self.master_fd)
        except Exception:
            pass
        self.master_fd = None
        self.proc = None

    def hard_reset(self) -> str:
        self.shutdown()
        self._sent = "@@PWNDBGMCP_EOC_" + uuid.uuid4().hex[:8] + "@@"
        return self.start()

    # ----------------------------------------------------------------- low level
    def _drain(self):
        if self.master_fd is None:
            return
        while True:
            r, _, _ = select.select([self.master_fd], [], [], 0)
            if not r:
                break
            try:
                if not os.read(self.master_fd, 65536):
                    break
            except OSError:
                break

    def _sent_or_prompt(self):
        return self._sent

    def _read_until(self, marker: str, timeout: float = 20.0,
                    idle: float | None = None, prime: bool = False) -> str:
        """Read until `marker` appears, or until idle/timeout elapses."""
        if self.master_fd is None:
            raise GdbError("gdb session is not running")
        deadline = time.time() + timeout
        chunks: list[bytes] = []
        marker_b = marker.encode()
        last_data = time.time()
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            r, _, _ = select.select([self.master_fd], [], [], min(0.2, remaining))
            if r:
                try:
                    data = os.read(self.master_fd, 65536)
                except OSError:
                    break
                if not data:
                    break
                chunks.append(data)
                last_data = time.time()
                if marker_b in b"".join(chunks):
                    break
            else:
                if idle is not None and (time.time() - last_data) >= idle:
                    break
                if prime and not chunks and (time.time() - last_data) >= idle:
                    break
        raw = b"".join(chunks)
        self.last_raw = raw
        return strip_ansi(raw)

    def _clean(self, text: str, command: str) -> str:
        # cut everything from the sentinel onward
        idx = text.find(self._sent)
        if idx != -1:
            text = text[:idx]
        lines = text.split("\n")
        out = []
        cmd_first = command.strip().split("\n")[0].strip()
        prompts = {"pwndbg>", ">", "(gdb)", "pwndbg legend>"}

        def is_prompt(s: str) -> bool:
            t = s.strip()
            return t in prompts or t.startswith("pwndbg> ")

        for ln in lines:
            s = ln.rstrip()
            if self._sent in s:
                continue
            # a bare prompt line is noise wherever it appears
            if is_prompt(s):
                # but a prompt may prefix real output (rare with editing off)
                rest = s.strip()
                if rest.startswith("pwndbg> "):
                    rest = rest[len("pwndbg> "):].strip()
                    if rest:
                        out.append(rest)
                continue
            if s.strip() == cmd_first and not out:
                # drop the leading echoed command line
                continue
            out.append(s)
        # trim leading/trailing blank lines
        while out and not out[0].strip():
            out.pop(0)
        while out and not out[-1].strip():
            out.pop()
        return compact("\n".join(out))

    # ----------------------------------------------------------------- public API
    def cmd(self, command: str, timeout: float = 20.0,
            idle: float | None = None) -> str:
        """Run a gdb/pwndbg command and return its (ANSI-stripped) output.

        For commands that hand control to a running inferior (run/continue),
        pass idle>0 so we return after the program goes quiet instead of
        blocking for the sentinel.
        """
        if not self.is_alive():
            raise GdbError("gdb session is dead; call hard_reset")
        self._drain()
        marker = self._sent
        payload = command + "\n" + "echo \\n" + self._sent + "\\n\n"
        os.write(self.master_fd, payload.encode())
        text = self._read_until(marker, timeout=timeout, idle=idle)
        return self._clean(text, command)

    def run_inferior(self, run_cmd: str = "run", timeout: float = 10.0,
                     idle: float = 0.5) -> str:
        """Start/continue the inferior; return output once it goes idle/stops.

        No sentinel is appended: a resumed inferior shares the PTY stdin, so an
        echoed sentinel would be swallowed by the program's read()/scanf().
        We return once output goes idle (program stopped or waiting on input).
        """
        if not self.is_alive():
            raise GdbError("gdb session is dead; call hard_reset")
        self._drain()
        os.write(self.master_fd, (run_cmd + "\n").encode())
        text = self._read_until(self._sent, timeout=timeout, idle=idle)
        return self._clean(text, run_cmd)

    # resume covers run / continue / finish / until / stepi / nexti / step / next
    resume = run_inferior

    def send_process(self, data: bytes, read_after: float = 0.4,
                     timeout: float = 5.0) -> str:
        """Write raw bytes to the inferior's stdin (via the PTY)."""
        if self.master_fd is None:
            raise GdbError("no session")
        os.write(self.master_fd, data)
        return self._read_until(self._sent, timeout=timeout, idle=read_after)

    def read_process(self, read_after: float = 0.4, timeout: float = 5.0) -> str:
        return self._read_until(self._sent, timeout=timeout, idle=read_after)

    def interrupt(self) -> str:
        os.write(self.master_fd, b"\x03")
        return self._read_until(self._sent, timeout=5.0, idle=0.5)
