"""Who may approve a pending command, and when enough of them have.

Pure logic, no I/O. Everything else in second-key (Telegram delivery, hooks, the ledger)
feeds this module and acts on what it returns.

The rule: the person whose message raised the approval can never answer it. The other
approvers on the roster can, and a request needs ``required`` distinct yes votes from them.
One no from any eligible approver denies it at once.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Iterable, Optional


@dataclass(frozen=True)
class Approver:
    """One person on the roster. ``telegram_id`` is where second-key DMs them; ``aliases`` are
    the ids the same person has on other chat platforms (``"discord:1234"``), so a request they
    start from Discord still counts as theirs."""

    name: str
    telegram_id: str
    aliases: tuple[str, ...] = ()

    def identity_keys(self) -> frozenset[str]:
        return frozenset({f"telegram:{self.telegram_id}", *self.aliases})


@dataclass(frozen=True)
class Requester:
    """Who raised the approval. ``platform``/``user_id`` come from the session that started the
    turn. Both empty means the turn came from a local surface (CLI, TUI, Desktop) or the id was
    not bound, and second-key cannot tell who asked."""

    platform: str = ""
    user_id: str = ""

    @property
    def known(self) -> bool:
        return bool(self.platform and self.user_id)

    @property
    def key(self) -> str:
        return f"{self.platform}:{self.user_id}" if self.known else ""


@dataclass(frozen=True)
class Policy:
    approvers: tuple[Approver, ...]
    required: int = 1
    critical_required: int = 2
    critical_patterns: tuple[str, ...] = ()
    unknown_requester_required: int = 2

    def compiled_critical(self) -> list[re.Pattern]:
        return [re.compile(p) for p in self.critical_patterns]


def required_votes(policy: Policy, command: str, requester: Requester) -> tuple[int, str]:
    """How many distinct yes votes this request needs, and why. The largest applicable rule wins."""
    need, reason = max(1, policy.required), "default"
    for pattern in policy.compiled_critical():
        if pattern.search(command or ""):
            if policy.critical_required > need:
                need, reason = policy.critical_required, f"critical pattern {pattern.pattern!r}"
            break
    if not requester.known and policy.unknown_requester_required > need:
        need, reason = policy.unknown_requester_required, "requester unknown"
    return need, reason


def eligible_approvers(policy: Policy, requester: Requester) -> list[Approver]:
    """The roster minus the requester."""
    return [a for a in policy.approvers if not (requester.known and requester.key in a.identity_keys())]


@dataclass
class Ballot:
    """Votes on one request. Thread-safe: Telegram callbacks land on the poller thread while the
    transport worker waits on ``done``."""

    request_id: str
    requester: Requester
    required: int
    reason: str
    eligible: tuple[Approver, ...]
    yes: dict[str, str] = field(default_factory=dict)   # telegram_id -> name
    no: Optional[str] = None                             # name of the approver who denied
    ignored: list[str] = field(default_factory=list)    # why a vote was refused, for the ledger
    done: threading.Event = field(default_factory=threading.Event)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def impossible(self) -> bool:
        return len(self.eligible) < self.required

    def vote(self, telegram_id: str, choice: str) -> str:
        """Record one vote; returns ``"counted"``, ``"ignored:<why>"`` or the final ``"approved"`` /
        ``"denied"`` once the ballot closes. A closed ballot ignores further votes."""
        voter = str(telegram_id)
        with self._lock:
            if self.done.is_set():
                return "ignored:closed"
            if self.requester.known and self.requester.key == f"telegram:{voter}":
                self.ignored.append(f"requester {voter} tried to approve their own request")
                return "ignored:requester"
            match = next((a for a in self.eligible if a.telegram_id == voter), None)
            if match is None:
                self.ignored.append(f"{voter} is not an eligible approver")
                return "ignored:not-eligible"
            if choice == "deny":
                self.no = match.name
                self.done.set()
                return "denied"
            if choice != "once":
                self.ignored.append(f"{match.name} sent unsupported choice {choice!r}")
                return "ignored:choice"
            self.yes[voter] = match.name
            if len(self.yes) >= self.required:
                self.done.set()
                return "approved"
            return "counted"

    @property
    def outcome(self) -> str:
        with self._lock:
            if self.no is not None:
                return "deny"
            return "once" if len(self.yes) >= self.required else "deny"


def open_ballot(policy: Policy, request_id: str, command: str, requester: Requester) -> Ballot:
    need, reason = required_votes(policy, command, requester)
    ballot = Ballot(request_id=request_id, requester=requester, required=need, reason=reason,
                    eligible=tuple(eligible_approvers(policy, requester)))
    if ballot.impossible:
        ballot.done.set()  # fail closed: not enough people besides the requester to ever approve
    return ballot


def parse_policy(cfg: dict) -> Policy:
    """Build a Policy from the plugin's settings. Bad entries raise ValueError so the plugin
    refuses to arm instead of running with a roster nobody intended."""
    raw = cfg.get("approvers") or []
    if not isinstance(raw, list):
        raise ValueError("approvers must be a list")
    approvers: list[Approver] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict) or not str(entry.get("telegram_id", "")).strip():
            raise ValueError("each approver needs a telegram_id")
        tid = str(entry["telegram_id"]).strip()
        if not tid.lstrip("-").isdigit():
            raise ValueError(f"telegram_id {tid!r} is not a numeric Telegram user id")
        if tid in seen:
            raise ValueError(f"approver telegram_id {tid} listed twice")
        seen.add(tid)
        aliases = tuple(str(a).strip() for a in entry.get("aliases") or [] if ":" in str(a))
        approvers.append(Approver(name=str(entry.get("name") or tid), telegram_id=tid, aliases=aliases))
    patterns = tuple(str(p) for p in cfg.get("critical_patterns") or [])
    for p in patterns:
        re.compile(p)
    return Policy(
        approvers=tuple(approvers),
        required=_positive_int(cfg.get("required", 1), "required"),
        critical_required=_positive_int(cfg.get("critical_required", 2), "critical_required"),
        critical_patterns=patterns,
        unknown_requester_required=_positive_int(cfg.get("unknown_requester_required", 2),
                                                 "unknown_requester_required"),
    )


def _positive_int(value, name: str) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a whole number") from None
    if n < 1:
        raise ValueError(f"{name} must be at least 1")
    return n


def roster_ids(policy: Policy) -> frozenset[str]:
    keys: set[str] = set()
    for a in policy.approvers:
        keys |= a.identity_keys()
    return frozenset(keys)


def is_on_roster(policy: Policy, platform: str, user_id: str) -> bool:
    return bool(platform and user_id) and f"{platform}:{user_id}" in roster_ids(policy)


def describe(policy: Policy) -> Iterable[str]:
    yield f"{len(policy.approvers)} approver(s); requester never counts"
    yield f"default: {policy.required} yes vote(s) from someone other than the requester"
    if policy.critical_patterns:
        yield f"critical patterns ({len(policy.critical_patterns)}): {policy.critical_required} yes votes"
    yield f"requester unknown: {policy.unknown_requester_required} yes votes"
