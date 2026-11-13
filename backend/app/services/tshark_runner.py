"""Controlled TShark subprocess wrapper.

* No shell, argument list only.
* The only user-influenced argument is the capture path, which is always a file
  we created inside the uploads directory.
* Display filters / decode-as entries are built by this module from validated
  integers and a protocol whitelist; arbitrary strings are never forwarded.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Iterator

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("tshark")

ALLOWED_DECODE_AS = {"smtp", "imap", "pop", "tls"}
_FILTER_OK = re.compile(r"^[A-Za-z0-9_.&|!=<>(){}\s,:\"-]*$")
FIELD_OK = re.compile(r"^[a-z0-9_.]+$")


class TsharkError(RuntimeError):
    pass


class TsharkNotFound(TsharkError):
    pass


class AnalysisCancelled(TsharkError):
    pass


_active: dict[str, subprocess.Popen] = {}
_cancelled: set[str] = set()
_lock = threading.Lock()


def find_tshark() -> str | None:
    if settings.tshark_path:
        p = Path(settings.tshark_path)
        return str(p) if p.is_file() else None
    return shutil.which("tshark")


def tool_info() -> dict:
    path = find_tshark()
    info: dict = {"available": False, "path": path, "version": None, "editcap": shutil.which("editcap")}
    if not path:
        info["error"] = "TShark was not found. Install Wireshark's command-line tools (e.g. `sudo apt install tshark`, `sudo pacman -S wireshark-cli`, `brew install wireshark`) or set SMS_TSHARK_PATH."
        return info
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10, check=False).stdout
        info["version"] = out.splitlines()[0].strip() if out else None
        info["available"] = True
    except Exception as exc:  # pragma: no cover - defensive
        info["error"] = f"TShark could not be executed: {exc}"
    return info


def require_tshark() -> str:
    path = find_tshark()
    if not path:
        raise TsharkNotFound(tool_info()["error"])
    return path


def request_cancel(analysis_id: str) -> None:
    with _lock:
        _cancelled.add(analysis_id)
        proc = _active.get(analysis_id)
    if proc and proc.poll() is None:
        proc.kill()


def clear_cancel(analysis_id: str) -> None:
    with _lock:
        _cancelled.discard(analysis_id)


def is_cancelled(analysis_id: str | None) -> bool:
    return bool(analysis_id) and analysis_id in _cancelled


def _decode_args(decode_as: list[tuple[int, str]] | None) -> list[str]:
    args: list[str] = []
    for port, proto in decode_as or []:
        if proto not in ALLOWED_DECODE_AS or not (0 < int(port) < 65536):
            raise ValueError("invalid decode-as entry")
        args += ["-d", f"tcp.port=={int(port)},{proto}"]
    return args


def _run(cmd: list[str], out_path: Path, analysis_id: str | None, timeout: int) -> None:
    if is_cancelled(analysis_id):
        raise AnalysisCancelled()
    with open(out_path, "wb") as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(cmd, stdout=out, stderr=err, stdin=subprocess.DEVNULL, shell=False)  # noqa: S603
        if analysis_id:
            with _lock:
                _active[analysis_id] = proc
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise TsharkError(f"TShark exceeded the {timeout}s processing limit") from None
        finally:
            if analysis_id:
                with _lock:
                    _active.pop(analysis_id, None)
        if is_cancelled(analysis_id):
            raise AnalysisCancelled()
        err.seek(0)
        stderr = err.read().decode("utf-8", "replace")
    if proc.returncode not in (0, 2):  # 2 = some packets malformed/truncated; still usable
        raise TsharkError(f"TShark failed (exit {proc.returncode}): {stderr.strip()[:400]}")
    if stderr.strip():
        log.info("tshark stderr: %s", stderr.strip()[:300])


def run_fields(
    pcap: Path,
    fields: list[str],
    *,
    display_filter: str | None = None,
    decode_as: list[tuple[int, str]] | None = None,
    analysis_id: str | None = None,
    two_pass: bool = False,
    timeout: int | None = None,
) -> Iterator[list[str]]:
    """Run ``tshark -T fields`` and yield rows (one list of strings per frame)."""
    exe = require_tshark()
    if not all(FIELD_OK.match(f) for f in fields):
        raise ValueError("invalid field name")
    if display_filter and not _FILTER_OK.match(display_filter):
        raise ValueError("invalid display filter")
    cmd = [exe, "-r", str(pcap), "-n", "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f", "-E", "header=n"]
    if two_pass:
        cmd.append("-2")
    cmd += _decode_args(decode_as)
    if display_filter:
        cmd += ["-Y", display_filter]
    for f in fields:
        cmd += ["-e", f]
    with tempfile.NamedTemporaryFile(suffix=".tsv", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _run(cmd, tmp_path, analysis_id, timeout or settings.analysis_timeout_s)
        with open(tmp_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                row = line.rstrip("\n").split("\t")
                row += [""] * (len(fields) - len(row))
                yield row
    finally:
        tmp_path.unlink(missing_ok=True)


def run_json(
    pcap: Path,
    *,
    display_filter: str,
    layers: str = "frame ip ipv6 tcp tls smtp imap pop",
    decode_as: list[tuple[int, str]] | None = None,
    analysis_id: str | None = None,
    raw_hex: bool = False,
    timeout: int | None = None,
) -> list[dict]:
    """Run a two-pass dissection and return the packets' ``layers`` dicts."""
    exe = require_tshark()
    if not _FILTER_OK.match(display_filter) or not re.fullmatch(r"[a-z0-9 ]+", layers):
        raise ValueError("invalid filter or layer list")
    cmd = [exe, "-r", str(pcap), "-n", "-2", "-T", "json", "--no-duplicate-keys", "-J", layers]
    if raw_hex:
        cmd.append("-x")
    cmd += _decode_args(decode_as)
    cmd += ["-Y", display_filter]
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _run(cmd, tmp_path, analysis_id, timeout or settings.analysis_timeout_s)
        if tmp_path.stat().st_size == 0:
            return []
        with open(tmp_path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise TsharkError(f"TShark produced unreadable JSON: {exc}") from exc
    finally:
        tmp_path.unlink(missing_ok=True)
    return [p["_source"]["layers"] for p in data]


def export_frames(pcap: Path, frame_numbers: list[int], out_path: Path, analysis_id: str | None = None) -> None:
    """Write the selected frames to a new capture (used to carve post-STARTTLS bytes)."""
    exe = require_tshark()
    if not frame_numbers:
        raise ValueError("no frames to export")
    expr = "frame.number in {" + ", ".join(str(int(n)) for n in frame_numbers) + "}"
    cmd = [exe, "-r", str(pcap), "-n", "-Y", expr, "-w", str(out_path), "-F", "pcap"]
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _run(cmd, tmp_path, analysis_id, settings.analysis_timeout_s)
    finally:
        tmp_path.unlink(missing_ok=True)


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]
