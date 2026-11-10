"""Read-only routes behind the second-key Approvals pane.

Hermes loads this file by path, so the plugin's own ``ledger.py``, ``quorum.py`` and ``tripwire.py``
are loaded the same way. Nothing here writes: the pane reads ``state.json`` (open and recent ballots,
written by the gateway process), ``armed.json`` and ``ledger.jsonl`` from the profile's plugin data
directory, and the current approval settings from ``config.yaml``. The router declares GET routes only.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path

from fastapi import APIRouter, Query

LEDGER_SHOWN = 14
STALE_AFTER = 10.0  # seconds past a ballot's deadline before a leftover entry is treated as a dead process's
HIDDEN_VIEW_KEYS = {"expected_transport", "settings"}

router = APIRouter()
_modules: dict = {}


def _sibling(name: str):
    if name not in _modules:
        path = Path(__file__).resolve().parent.parent / f"{name}.py"
        spec = importlib.util.spec_from_file_location(f"second_key_pane_{name}", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module  # dataclasses resolve their annotations through sys.modules
        spec.loader.exec_module(module)
        _modules[name] = module
    return _modules[name]


def _data_dir() -> Path:
    from plugins.plugin_storage import plugin_data_dir

    return plugin_data_dir("second-key")


def _read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _live_ballots(state: dict, now: float) -> list[dict]:
    """Open ballots from the gateway's state file, minus any whose deadline passed long ago."""
    return [b for b in state.get("ballots") or [] if now <= b.get("opened_at", 0) + b.get("timeout", 0) + STALE_AFTER]


def _armed(data: Path, state: dict) -> dict:
    tripwire = _sibling("tripwire")
    armed = _read_json(data / "armed.json") or {}
    view = armed.get("view") if armed.get("fingerprint") == tripwire.fingerprint(armed.get("view") or {}) else None
    reasons = list(state.get("tripped") or [])
    changed: set = set()
    if view is not None:
        try:
            from hermes_cli.config import load_config_readonly

            current = tripwire.watched(load_config_readonly() or {}, "second-key", view["expected_transport"])
            changed = set(tripwire.changes(view, current))
            reasons = reasons or sorted(changed) + tripwire.problems(current)
        except Exception as exc:  # an unreadable config is itself a reason the gate cannot be trusted
            reasons = reasons or [f"could not read config.yaml ({type(exc).__name__})"]
    shown = view or {}
    return {
        "state": "tripped" if reasons else "armed" if view is not None else "not armed",
        "reasons": reasons,
        "fingerprint": tripwire.fingerprint(view)[:16] if view is not None else "",
        "watched": [{"key": k, "value": _short(v), "changed": k in changed}
                    for k, v in sorted(shown.items()) if k not in HIDDEN_VIEW_KEYS],
    }


def _short(value) -> str:
    text = ", ".join(map(str, value)) if isinstance(value, list) else str(value)
    return (text or "none")[:60]


def _roster() -> list[dict]:
    try:
        from hermes_cli.config import load_config_readonly

        entry = ((load_config_readonly() or {}).get("plugins") or {}).get("entries", {}).get("second-key") or {}
        policy = _sibling("quorum").parse_policy(entry.get("settings") if "settings" in entry else entry.get("config") or {})
    except (ValueError, TypeError, AttributeError):  # a bad roster shows as empty; /secondkey names the error
        return []
    return [{"name": a.name} for a in policy.approvers]


def _detail(entry: dict) -> str:
    kind = entry.get("event")
    if kind == "decided":
        who = ", ".join(entry.get("yes") or []) or "no one"
        return f"{entry.get('outcome')}: yes from {who}" + (f", no from {entry['no']}" if entry.get("no") else "")
    if kind == "vote":
        return f"{entry.get('choice')} tap: {entry.get('result')}"
    if kind == "presented":
        return f"{entry.get('required')} needed, {entry.get('delivered')} delivered"
    if kind in ("refused", "delivery_failed", "tool_refused"):
        return str(entry.get("why") or entry.get("reason") or "")[:90]
    if kind == "tripwire":
        return "changed: " + ", ".join(entry.get("changed") or [])[:90]
    if kind == "armed":
        return f"{entry.get('how')} {entry.get('fingerprint', '')}"
    return str(entry.get("command") or "")[:90]


@router.get("/state")
def state(ledger: int = Query(LEDGER_SHOWN, ge=1, le=60)):
    """Everything the pane draws, in one read: ballots, armed settings, roster and the ledger chain."""
    data = _data_dir()
    now = time.time()
    saved = _read_json(data / "state.json") or {}
    book = _sibling("ledger").Ledger(data / "ledger.jsonl")
    entries, flags = book.entries(), book.audit()
    first = max(0, len(entries) - ledger)
    return {
        "now": now,
        "ballots": _live_ballots(saved, now),
        "recent": list(reversed(saved.get("recent") or [])),
        "armed": _armed(data, saved),
        "roster": _roster(),
        "ledger": {
            "total": len(entries), "ok": all(flags), "broken_at": flags.index(False) + 1 if not all(flags) else 0,
            "entries": [{"n": i + 1, "ts": e.get("ts", ""), "event": e.get("event", ""), "hash": e.get("hash", ""),
                         "prev": e.get("prev", ""), "ok": flags[i], "detail": _detail(e)}
                        for i, e in enumerate(entries) if i >= first],
        },
    }
