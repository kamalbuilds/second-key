"""Who may approve a pending command, and when enough of them have.

Pure logic, no I/O. Everything else in second-key (Telegram delivery, hooks, the ledger)
feeds this module and acts on what it returns.

The rule: the person whose message raised the approval can never answer it. The other
approvers on the roster can, and a request needs ``required`` distinct yes votes from them.
One no from any eligible approver denies it at once.

A local session (CLI, TUI, Desktop) binds an id like ``local:uid:501`` that no roster entry
carries, so second-key cannot tell whether the machine owner is also an approver. Such a requester
counts as unknown, and ``unknown_requester_required`` applies, until an approver lists that id in
``aliases``: then that approver is excluded as the requester and the normal rule applies.
"""

from __future__ import annotations

import re
import shlex
import threading
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional


LOCAL_PLATFORMS = frozenset({"local", "cli", "tui", "desktop", "acp"})

# Used when ``critical_patterns`` is not configured. A configured list, even an empty one, replaces it.
# Each pattern is tried against the command as written and against its normalised forms (see
# ``command_forms``): shell payloads unwrapped, chained commands split, short flags expanded so
# ``rm -fr`` and ``rm --recursive --force`` both read ``rm -r -f``. This is a default list of common
# destructive commands, not a complete one: a command it does not name is an ordinary request.
_ARGS = r"[^;|&]*"
_DEFAULTS = (
    (r"\brm\b(?=" + _ARGS + r"\s-r\b)(?=" + _ARGS + r"\s-f\b)", "rm -rf"),
    (r"\bfind\b" + _ARGS + r"\s-delete\b", "find -delete"),
    (r"\bfind\b" + _ARGS + r"-exec\s+rm\b", "find -exec rm"),
    (r"\b(shutil\.rmtree|os\.(remove|unlink|rmdir|removedirs))\b", "script deleting files"),
    (r"\b(shred|wipefs)\b", "shred / wipefs"),
    (r"\btruncate\s+(-|table\b)", "truncate"),
    (r"\bdrop\s+(table|database|schema|index|view|user|role|extension)\b", "drop table / database"),
    (r"\bgit\s+reset\b" + _ARGS + r"--hard\b", "git reset --hard"),
    (r"\bgit\s+clean\b" + _ARGS + r"\s-f\b", "git clean -f"),
    (r"\bgit\s+branch\b" + _ARGS + r"\s(?-i:-D)\b", "git branch -D"),
    (r"\bgit\s+push\b" + _ARGS + r"\s(-f|--force|--force-with-lease)\b", "git push --force"),
    (r"\b(chmod|chown|chgrp)\b" + _ARGS + r"\s-r\b", "recursive chmod / chown"),
    (r"\bmk(e2)?fs(\.\w+)?\b", "make filesystem"),
    (r"\bdd\b.*\bof=/dev/", "dd to a device"),
    (r"\b(terraform|tofu|pulumi)\s+destroy\b", "terraform destroy"),
    (r"\b(terraform|tofu)\s+apply\b" + _ARGS + r"-destroy\b", "terraform apply -destroy"),
    (r"\bkubectl\s+delete\s+(namespaces?|ns|nodes?|pv|pvc|persistentvolumes?(claims?)?|crd|"
     r"customresourcedefinitions?|deployments?|statefulsets?|daemonsets?|clusters?)\b", "kubectl delete"),
    (r"\bkubectl\s+delete\b" + _ARGS + r"\s--all\b", "kubectl delete --all"),
    (r"\bhelm\s+(uninstall|delete)\b", "helm uninstall"),
    (r"\bdocker\s+((system|volume|image|container|network)\s+prune|volume\s+rm)\b", "docker prune"),
    (r"\baws\s+s3\s+rb\b", "aws s3 rb"),
    (r"\baws\s+s3\s+rm\b" + _ARGS + r"--recursive\b", "aws s3 rm --recursive"),
    (r"\baws\b" + _ARGS + r"\b(terminate|delete)-[a-z-]+\b", "aws delete / terminate"),
    (r"\b(gcloud|az|doctl|heroku|flyctl|railway)\b" + _ARGS + r"\b(delete|destroy)\b", "cloud delete"),
)
DEFAULT_CRITICAL_PATTERNS = tuple(p for p, _ in _DEFAULTS)
DEFAULT_LABELS = dict(_DEFAULTS)

_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish"})
_LONG_FLAGS = {"--recursive": "-r", "--force": "-f"}
_MAX_FORMS = 64
_MAX_COMMAND = 8000
_MAX_DEPTH = 4


def _expand_flags(tokens: list[str]) -> list[str]:
    """``-rfv`` becomes ``-r -f -v``, ``-R`` becomes ``-r``, ``--recursive`` becomes ``-r``. A token that
    is not a short-flag cluster (``-delete`` for find, ``-D``) is left alone, so both readings exist."""
    out: list[str] = []
    for tok in tokens:
        if tok in _LONG_FLAGS:
            out.append(_LONG_FLAGS[tok])
        elif re.fullmatch(r"-[A-Za-z]{2,}", tok):
            out.extend(f"-{c.lower()}" for c in tok[1:])
        elif re.fullmatch(r"-[A-Z]", tok):
            out.append(tok.lower())
        else:
            out.append(tok)
    return out


def command_forms(command: str, _depth: int = 0) -> list[str]:
    """The command as written plus its normalised readings, so a pattern cannot be dodged by flag order,
    combined flags, ``;``/``&&``/``|`` chains or an ``sh -c '...'`` wrapper. Bounded in size and depth."""
    command = (command or "")[:_MAX_COMMAND]
    forms = [command]
    if _depth >= _MAX_DEPTH:
        return forms
    lexer = shlex.shlex(command.replace("\n", " ; "), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:  # unbalanced quotes: read it as plain words rather than refuse to look
        tokens = command.split()
    simple: list[list[str]] = [[]]
    for tok in tokens:
        if tok and set(tok) <= set(";&|()"):
            simple.append([])
        else:
            simple[-1].append(tok)
    for words in (w for w in simple if w):
        forms.append(" ".join(words))
        forms.append(" ".join(_expand_flags(words)))
        for i, word in enumerate(words[:-1]):
            if word.rsplit("/", 1)[-1] in _SHELLS and any(re.fullmatch(r"-[a-z]*c[a-z]*", w) for w in words[i + 1:-1]):
                forms.extend(command_forms(words[-1], _depth + 1))
                break
        if len(forms) >= _MAX_FORMS:
            break
    return forms[:_MAX_FORMS]


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
        return f"{self.platform.lower()}:{self.user_id}" if self.known else ""


@dataclass(frozen=True)
class Policy:
    approvers: tuple[Approver, ...]
    required: int = 1
    critical_required: int = 2
    critical_patterns: tuple[str, ...] = DEFAULT_CRITICAL_PATTERNS
    unknown_requester_required: int = 2
    patterns_configured: bool = False

    def compiled_critical(self) -> list[re.Pattern]:
        return [re.compile(p, re.IGNORECASE) for p in self.critical_patterns]


def identified(policy: Policy, requester: Requester) -> bool:
    """Whether second-key can say who asked. A local requester is identified only when an approver
    lists its id in ``aliases``; otherwise the machine owner could be anyone, approvers included."""
    if not requester.known:
        return False
    if requester.platform.lower() in LOCAL_PLATFORMS:
        return any(requester.key in a.identity_keys() for a in policy.approvers)
    return True


def required_votes(policy: Policy, command: str, requester: Requester) -> tuple[int, str]:
    """How many distinct yes votes this request needs, and why. The largest applicable rule wins."""
    need, reason = max(1, policy.required), "default"
    forms = command_forms(command)
    for pattern in policy.compiled_critical():
        if any(pattern.search(form) for form in forms):
            if policy.critical_required > need:
                label = DEFAULT_LABELS.get(pattern.pattern)
                need, reason = policy.critical_required, f"critical pattern: {label}" if label else f"critical pattern {pattern.pattern!r}"
            break
    if not identified(policy, requester) and policy.unknown_requester_required > need:
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
    excluded: frozenset[str] = frozenset()               # telegram ids of approvers who are the requester
    yes: dict[str, str] = field(default_factory=dict)   # telegram_id -> name
    no: Optional[str] = None                             # name of the approver who denied
    ignored: list[str] = field(default_factory=list)    # why a vote was refused, for the ledger
    roster: tuple[Approver, ...] = ()                    # everyone on the roster, for the live views
    tier: str = "standard"                               # "critical", "unknown requester" or "standard"
    timeout: float = 0.0                                 # seconds Hermes gave this request
    opened_at: float = field(default_factory=time.time)
    not_counted: list[dict] = field(default_factory=list)  # taps that were refused: voter, name, why
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
            if voter in self.excluded or (self.requester.known and self.requester.key == f"telegram:{voter}"):
                self.ignored.append(f"requester {voter} tried to approve their own request")
                self._refuse(voter, "requester")
                return "ignored:requester"
            match = next((a for a in self.eligible if a.telegram_id == voter), None)
            if match is None:
                self.ignored.append(f"{voter} is not an eligible approver")
                self._refuse(voter, "not-eligible")
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

    def _refuse(self, voter: str, why: str) -> None:
        name = next((a.name for a in self.roster if a.telegram_id == voter), voter)
        self.not_counted.append({"voter": voter, "name": name, "why": why, "at": time.time()})

    def squares(self) -> str:
        """One square per required vote, filled for each yes: ``■□``."""
        with self._lock:
            return "■" * min(len(self.yes), self.required) + "□" * max(0, self.required - len(self.yes))

    def progress(self) -> str:
        with self._lock:
            names = ", ".join(sorted(self.yes.values()))
            return f"{len(self.yes)} of {self.required} approved" + (f": {names}" if names else "")

    def waiting_on(self) -> list[str]:
        with self._lock:
            return [a.name for a in self.eligible if a.telegram_id not in self.yes]

    def snapshot(self) -> dict:
        """The live state of this ballot, for the Desktop pane. Names only: ids stay in the ledger."""
        with self._lock:
            def state(a: Approver) -> str:
                if a.telegram_id in self.excluded:
                    return "requester"
                if a.name == self.no:
                    return "no"
                return "yes" if a.telegram_id in self.yes else "waiting"
            return {
                "request_id": self.request_id, "required": self.required, "reason": self.reason, "tier": self.tier,
                "opened_at": self.opened_at, "timeout": self.timeout,
                "approvers": [{"name": a.name, "state": state(a)} for a in self.roster or self.eligible],
                "not_counted": [{"name": n["name"], "why": n["why"], "at": n["at"]} for n in self.not_counted],
            }

    @property
    def outcome(self) -> str:
        with self._lock:
            if self.no is not None:
                return "deny"
            return "once" if len(self.yes) >= self.required else "deny"


def risk_tier(reason: str) -> str:
    if reason.startswith("critical"):
        return "critical"
    return "unknown requester" if reason == "requester unknown" else "standard"


def open_ballot(policy: Policy, request_id: str, command: str, requester: Requester,
                timeout: float = 0.0) -> Ballot:
    need, reason = required_votes(policy, command, requester)
    ballot = Ballot(request_id=request_id, requester=requester, required=need, reason=reason,
                    roster=policy.approvers, tier=risk_tier(reason), timeout=timeout,
                    eligible=tuple(eligible_approvers(policy, requester)),
                    excluded=frozenset(a.telegram_id for a in policy.approvers
                                       if requester.known and requester.key in a.identity_keys()))
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
    seen_keys: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict) or not str(entry.get("telegram_id", "")).strip():
            raise ValueError("each approver needs a telegram_id")
        tid = str(entry["telegram_id"]).strip()
        if not tid.isdigit() or int(tid) <= 0:
            raise ValueError(f"telegram_id {tid!r} is not a positive numeric Telegram user id")
        if tid in seen:
            raise ValueError(f"approver telegram_id {tid} listed twice")
        seen.add(tid)
        aliases = tuple(_alias(a) for a in entry.get("aliases") or [])
        for key in (f"telegram:{tid}", *aliases):
            if key in seen_keys:
                raise ValueError(f"identity {key} is listed for two approvers")
            seen_keys.add(key)
        approvers.append(Approver(name=str(entry.get("name") or tid), telegram_id=tid, aliases=aliases))
    configured = cfg.get("critical_patterns") is not None
    if configured and not isinstance(cfg["critical_patterns"], list):
        raise ValueError("critical_patterns must be a list")
    patterns = tuple(str(p) for p in cfg["critical_patterns"]) if configured else DEFAULT_CRITICAL_PATTERNS
    for p in patterns:
        re.compile(p, re.IGNORECASE)
    return Policy(
        approvers=tuple(approvers),
        required=_positive_int(cfg.get("required", 1), "required"),
        critical_required=_positive_int(cfg.get("critical_required", 2), "critical_required"),
        critical_patterns=patterns,
        patterns_configured=configured,
        unknown_requester_required=_positive_int(cfg.get("unknown_requester_required", 2),
                                                 "unknown_requester_required"),
    )


def _alias(value) -> str:
    text = str(value).strip()
    platform, sep, user_id = text.partition(":")
    if not sep or not platform.strip() or not user_id.strip():
        raise ValueError(f"alias {text!r} must look like platform:user_id")
    return f"{platform.strip().lower()}:{user_id.strip()}"


def _positive_int(value, name: str) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a whole number") from None
    if n < 1:
        raise ValueError(f"{name} must be at least 1")
    return n


def weakened(old_settings: dict | None, new_settings: dict | None) -> list[str]:
    """What a settings change gives up. Fewer approvers, fewer votes required, a dropped critical
    pattern and an alias that identifies a local session each make approvals easier to get, so
    re-arming after one needs the armed roster's say. More approvers, more votes and more patterns
    do not."""
    try:
        old = parse_policy(old_settings or {})
    except ValueError as exc:
        return [f"armed settings do not parse: {exc}"]
    try:
        new = parse_policy(new_settings or {})
    except ValueError as exc:
        return [f"new settings do not parse: {exc}"]
    out = [f"approver {a.name} removed" for a in old.approvers
           if a.telegram_id not in {b.telegram_id for b in new.approvers}]
    out += [f"{key} {getattr(old, key)} to {getattr(new, key)}"
            for key in ("required", "critical_required", "unknown_requester_required")
            if getattr(new, key) < getattr(old, key)]
    out += [f"critical pattern dropped: {DEFAULT_LABELS.get(p, p)}"
            for p in old.critical_patterns if p not in new.critical_patterns]
    before = {a.telegram_id: set(a.aliases) for a in old.approvers}
    for a in new.approvers:
        out += [f"{a.name} now aliases {alias}" for alias in sorted(set(a.aliases) - before.get(a.telegram_id, set()))
                if alias.partition(":")[0] in LOCAL_PLATFORMS]
    return out


def describe(policy: Policy) -> Iterable[str]:
    yield f"{len(policy.approvers)} approver(s); requester never counts"
    yield f"default: {policy.required} yes vote(s) from someone other than the requester"
    if policy.critical_patterns:
        source = "configured" if policy.patterns_configured else "built-in default"
        yield f"critical patterns ({len(policy.critical_patterns)}, {source}): {policy.critical_required} yes votes"
    yield (f"requester unknown, or a local session no approver lists in aliases: "
           f"{policy.unknown_requester_required} yes votes")
