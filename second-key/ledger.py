"""Append-only, hash-chained record of every second-key decision.

Each line carries the SHA-256 of the line before it, so deleting or editing an earlier entry
breaks ``verify()``. It is tamper-evident on this machine, not tamper-proof: someone with write
access can rewrite the whole file. The README says exactly that.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

GENESIS = "0" * 64


class Ledger:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = ""
        with self.path.open("rb") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if not last:
            return GENESIS
        return json.loads(last)["hash"]

    def append(self, event: str, **fields) -> dict:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **fields,
                     "prev": self._last_hash()}
            entry["hash"] = _digest(entry)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return entry

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def tail(self, n: int) -> list[dict]:
        return self.entries()[-max(0, n):]

    def verify(self) -> tuple[bool, int]:
        """(True, 0) when every link holds; else (False, 1-based line number of the first break)."""
        prev = GENESIS
        for i, entry in enumerate(self.entries(), 1):
            claimed = entry.get("hash")
            body = {k: v for k, v in entry.items() if k != "hash"}
            if entry.get("prev") != prev or _digest(body) != claimed:
                return False, i
            prev = claimed
        return True, 0


def _digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
