"""The approval settings second-key armed with, and whether they still hold.

A command filter cannot stop an agent with a shell from editing Hermes' config: there are too
many ways to write a file. So second-key does not try to catch every write. It records the
settings that decide approvals when it is armed, compares them before every tool call, and if
they have changed it stops the agent's tools and tells the approvers. Re-arming is a deliberate
act by the profile owner from a local session.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _mode(value: Any) -> str:
    # YAML reads an unquoted `off` as False; Hermes treats that as approvals off.
    if value is False:
        return "off"
    return str(value or "").strip().lower()


def _list(value: Any) -> list:
    """Hermes accepts a bare string for command_allowlist; compare lists either way."""
    if isinstance(value, str):
        value = [value]
    return sorted(str(v) for v in value) if isinstance(value, (list, tuple)) else []


def watched(cfg: dict, plugin_key: str, transport: str) -> dict:
    """The parts of config.yaml that decide who approves what."""
    security = ((cfg.get("security") or {}).get("approval") or {})
    approvals = cfg.get("approvals") or {}
    plugins = cfg.get("plugins") or {}
    entry = (plugins.get("entries") or {}).get(plugin_key) or {}
    enabled = plugins.get("enabled")
    disabled = plugins.get("disabled")
    return {
        "transport": str(security.get("transport") or "builtin").strip().lower(),
        "transport_fallback": str(security.get("transport_fallback") or "").strip().lower(),
        "approvals_mode": _mode(approvals.get("mode")),
        "cron_mode": _mode(approvals.get("cron_mode")),
        "single_query_mode": _mode(approvals.get("single_query_mode")),
        "unattended_mode": _mode(approvals.get("unattended_mode")),
        # Hermes re-reads these on every approval, so a hand edit changes what needs a vote without
        # a restart: a command_allowlist entry (glob or pattern key like "recursive delete") is
        # waved through before the transport is called, and the others loosen or reroute the gate.
        "command_allowlist": _list(cfg.get("command_allowlist")),
        "approvals_deny": _list(approvals.get("deny")),
        "approvals_approvers": _list(approvals.get("approvers")),
        "approvals_smart_policy": str(approvals.get("smart_policy") or "").strip(),
        "approvals_timeout": str(approvals.get("timeout") or "").strip(),
        "isolation": str(plugins.get("isolation") or "").strip().lower(),
        "plugin_listed_enabled": plugin_key in (enabled or []) if isinstance(enabled, list) else None,
        "plugin_listed_disabled": plugin_key in (disabled or []) if isinstance(disabled, list) else False,
        "settings": entry.get("settings") if "settings" in entry else entry.get("config"),
        "expected_transport": transport,
    }


def problems(view: dict) -> list[str]:
    """Settings under which second-key is installed but is not deciding approvals."""
    out = []
    if view["transport"] != view["expected_transport"]:
        out.append(f"security.approval.transport is {view['transport']!r}, not {view['expected_transport']!r}")
    if view["transport_fallback"] == "builtin":
        out.append("transport_fallback: builtin lets a failed transport fall back to the chat prompt")
    if view["approvals_mode"] in {"off", "smart"}:
        out.append(f"approvals.mode is {view['approvals_mode']!r}: Hermes decides some commands without asking")
    for key, where in (("cron_mode", "cron jobs"), ("single_query_mode", "hermes -q runs"),
                       ("unattended_mode", "webhook and API sessions")):
        if view[key] == "approve":
            out.append(f"approvals.{key} is 'approve': flagged commands in {where} run with no vote")
    if view["isolation"] == "host":
        out.append("plugins.isolation: host is set; approval transports need in-process plugins")
    if view["plugin_listed_disabled"]:
        out.append("second-key is listed under plugins.disabled")
    return out


def fingerprint(view: dict) -> str:
    return hashlib.sha256(json.dumps(view, sort_keys=True, default=str).encode()).hexdigest()


def changes(before: dict, after: dict) -> list[str]:
    """Which watched settings differ, by name only (values can be long or sensitive)."""
    return sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
