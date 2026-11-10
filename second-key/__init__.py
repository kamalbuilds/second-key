"""second-key: the person who asks for a dangerous command can never be the one who approves it.

Selected with ``security.approval.transport: secondkey``. Dangerous terminal commands and
execute_code scripts that Hermes routes to its approval transport are sent by Telegram DM to the
approvers on a roster. The requester's own vote is never counted, critical commands need more yes
votes, and any error, timeout, unidentified sender or missing configuration is a deny, which Hermes
enforces host-side. Chat commands and tool calls that would switch approvals off are refused.
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import quorum, tripwire
from .ledger import Ledger
from .telegram import BotClient, Poller, TelegramError

logger = logging.getLogger(__name__)

TRANSPORT = "secondkey"
TOKEN_ENV = "SECONDKEY_TELEGRAM_BOT_TOKEN"
_BINDING_TTL = 900.0  # an approval is presented within seconds of its hook; stale bindings expire
MAX_COMMAND_CHARS = 3000  # Telegram messages cap at 4096; approvers must see the whole command
_GATED_COMMANDS = frozenset({"yolo", "approvals"})
# /loop, /queue, /bg, /steer and friends replay their argument later as an internal event, which
# skips this hook, so a gated command inside any slash command is refused here.
_GATED_TOKEN = re.compile(r"(^|\s)/(yolo|approvals)\b", re.IGNORECASE)
TELEGRAM_ANONYMOUS_ADMIN = "1087968824"  # GroupAnonymousBot: an anonymous group admin, not a person

REFRESH_SECONDS = 15.0  # how often an open ballot's remaining time is rewritten in the DMs
RECENT_KEPT = 8


@dataclass
class _Live:
    """One open ballot and the Telegram messages that show it."""

    request: Any
    requester: quorum.Requester
    name: str
    ballot: quorum.Ballot
    deadline: float                                   # time.monotonic() when Hermes gives up
    targets: list = field(default_factory=list)       # (chat_id, message_id, audience)
    lock: threading.Lock = field(default_factory=threading.Lock)
    closed: bool = False                              # set before the closing edit; later refreshes stand down


_ctx: Any = None
_bindings: dict[str, tuple[quorum.Requester, str, float, contextvars.Context, str]] = {}
_ballots: dict[str, quorum.Ballot] = {}
_lives: dict[str, _Live] = {}
_recent: list[dict] = []
_state_lock = threading.Lock()
_publish_lock = threading.Lock()  # the poller and the ballot's own thread both publish; one writer at a time
_client: BotClient | None = None
_poller: Poller | None = None
_ledger: Ledger | None = None
_enroll_until = 0.0
ENROLL_SECONDS = 300


# ---------------------------------------------------------------- helpers

def _session(name: str) -> str:
    from gateway.session_context import get_session_env
    return str(get_session_env(name, "") or "").strip()


def _policy() -> quorum.Policy:
    cfg = {k: _ctx.get_config(k) for k in
           ("approvers", "required", "critical_required", "critical_patterns", "unknown_requester_required")}
    return quorum.parse_policy({k: v for k, v in cfg.items() if v is not None})


def _bot() -> tuple[BotClient, Poller]:
    global _client, _poller
    with _state_lock:
        if _client is None:
            from agent.secret_scope import get_secret
            token = get_secret(TOKEN_ENV)
            if not token:
                raise TelegramError(f"{TOKEN_ENV} is not set")
            _client = BotClient(token)
            _poller = Poller(_client, _on_vote, _on_start, wanted=_poll_wanted)
        return _client, _poller


def _poll_wanted() -> bool:
    """Read the bot only while a ballot waits for votes or enrollment is on."""
    return bool(_ballots) or time.monotonic() < _enroll_until


def _get_ledger() -> Ledger:
    global _ledger
    with _state_lock:  # two Ledger objects would each lock alone and fork the hash chain
        if _ledger is None:
            from plugins.plugin_storage import plugin_data_dir
            _ledger = Ledger(plugin_data_dir("second-key") / "ledger.jsonl")
        return _ledger


def _record(event: str, **fields) -> dict | None:
    try:
        return _get_ledger().append(event, **fields)
    except Exception as exc:  # a broken ledger never approves: _present denies when "decided" is not written
        logger.error("second-key: ledger write failed for %r (%s: %s)", event, type(exc).__name__, exc)
        return None


def _state_file() -> Path:
    from plugins.plugin_storage import plugin_data_dir
    return plugin_data_dir("second-key") / "state.json"


def _publish() -> None:
    """Write what the Desktop pane shows: open ballots, the last few closed ones and any trip.
    The pane's backend reads this file; the ledger stays the record of truth."""
    with _publish_lock:
        with _state_lock:
            ballots = []
            for live in _lives.values():
                ballots.append({**live.ballot.snapshot(), "command": live.request.command,
                                "description": live.request.description, "pattern_key": live.request.pattern_key,
                                "requester": {"name": live.name, "platform": live.requester.platform or "local",
                                              "key": live.requester.key}})
            state = {"updated": time.time(), "ballots": ballots, "recent": list(_recent), "tripped": list(_tripped)}
        try:
            path = _state_file()
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(state, sort_keys=True))
            tmp.replace(path)
        except OSError as exc:
            logger.warning("second-key: could not write the pane state (%s)", type(exc).__name__)


def _expire_bindings(now: float) -> None:
    for rid in [r for r, b in _bindings.items() if now - b[2] > _BINDING_TTL]:
        _bindings.pop(rid, None)


# ---------------------------------------------------------------- hooks

def _on_pre_approval_request(request_id: str = "", **kwargs) -> None:
    """Runs on the agent's own thread, where the turn's session identity, Hermes home override and
    profile secret scope are bound. The transport worker that Hermes starts next is a fresh thread
    without any of them, so bind the requester here and keep a copy of this context for present()."""
    if not request_id:
        return
    # ACTOR_ID is the person whose message started this turn; in a shared (observe-mode) group
    # USER_ID is empty and only ACTOR_ID carries the sender.
    requester = quorum.Requester(platform=_session("HERMES_SESSION_PLATFORM").lower(),
                                 user_id=_session("HERMES_SESSION_ACTOR_ID") or _session("HERMES_SESSION_USER_ID"))
    name = (_session("HERMES_SESSION_ACTOR_NAME") or _session("HERMES_SESSION_USER_NAME")
            or requester.user_id)
    chat_id = _session("HERMES_SESSION_CHAT_ID")
    with _state_lock:
        now = time.monotonic()
        _expire_bindings(now)
        _bindings[request_id] = (requester, name, now, contextvars.copy_context(), chat_id)


def _command_of(event) -> str:
    """The slash command Hermes will run for this message, parsed the way Hermes parses it
    (attachment prefixes and @bot suffixes stripped), with a raw-text fallback."""
    get = getattr(event, "get_command", None)
    if callable(get):
        try:
            return str(get() or "").lower()
        except Exception:
            logger.debug("second-key: get_command failed; using raw text")
    for line in str(getattr(event, "text", "") or "").splitlines():
        line = line.strip()
        if not line or line.startswith("@"):  # attachment refs Hermes strips before the command
            continue
        first = line.split()[0]
        return first[1:].split("@", 1)[0].lower() if first.startswith("/") else ""
    return ""


def _on_pre_gateway_dispatch(event=None, **kwargs):
    """/yolo and /approvals switch Hermes' approvals off or down for the whole profile, which would
    let anyone approve their own command with no vote. While second-key is installed they are
    refused from every chat; the profile owner changes them from the local CLI."""
    command = _command_of(event)
    text = str(getattr(event, "text", "") or "")
    wrapped = bool(command) and _GATED_TOKEN.search(text) is not None
    if command not in _GATED_COMMANDS and not wrapped:
        return None
    src = getattr(event, "source", None)
    platform = getattr(getattr(src, "platform", None), "value", getattr(src, "platform", "")) or ""
    _record("command_refused", command=command, platform=str(platform),
            user_id=str(getattr(src, "user_id", "") or ""))
    return {"action": "skip", "reason": f"second-key: /{command} is not available from chats"}


# Narrow on purpose: the tripwire below catches config changes however they are made, so this
# only refuses the direct commands, without blocking ordinary work that mentions config files.
_TAMPER = re.compile(
    r"\bhermes\S*\s+(config\s+(set|unset|edit|migrate)|plugins?\s+(disable|remove|uninstall)"
    r"|approvals?\b|gateway\s+(restart|stop))|/secondkey\s+arm\b",
    re.IGNORECASE)
_WRITE_TOOLS = {"write_file", "patch", "edit_file", "apply_patch", "str_replace_editor", "create_file"}
_EXEC_TOOLS = {"terminal", "execute_code", "shell", "bash", "process"}
_LOCAL_SURFACES = {"", "local", "cli", "tui", "desktop", "acp"}

_armed_view: dict | None = None
_tripped: list[str] = []
_tripped_alerted = False
_cfg_stamp: tuple | None = None


def _arg_text(args) -> str:
    if isinstance(args, dict):
        return " ".join(str(v) for v in args.values() if isinstance(v, (str, int, float)))
    return str(args or "")


def _under(path: str, root) -> bool:
    try:
        return Path(path).expanduser().resolve().is_relative_to(Path(root).resolve())
    except (OSError, ValueError, RuntimeError):
        return False


def _names_own_data(text: str, data_dir) -> bool:
    """Whether text names this plugin's data directory, its ledger or its armed file."""
    return any(token in text for token in (str(data_dir), "plugin-data/second-key", "ledger.jsonl", "armed.json"))


def _config_path():
    from hermes_constants import get_hermes_home
    return get_hermes_home() / "config.yaml"


def _current_view() -> dict:
    from hermes_cli.config import load_config_readonly
    return tripwire.watched(load_config_readonly() or {}, "second-key", TRANSPORT)


def _armed_file():
    from plugins.plugin_storage import plugin_data_dir
    return plugin_data_dir("second-key") / "armed.json"


def _arm(view: dict) -> None:
    global _armed_view, _tripped, _tripped_alerted
    _armed_view = view
    _tripped, _tripped_alerted = [], False
    path = _armed_file()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"fingerprint": tripwire.fingerprint(view), "view": view}, sort_keys=True))
    tmp.replace(path)
    _publish()


def _load_armed() -> None:
    global _armed_view, _recent
    try:
        _recent = list(json.loads(_state_file().read_text()).get("recent") or [])[-RECENT_KEPT:]
    except (OSError, ValueError, AttributeError):
        _recent = []
    try:
        data = json.loads(_armed_file().read_text())
        if data.get("fingerprint") == tripwire.fingerprint(data.get("view") or {}):
            _armed_view = data["view"]
    except (OSError, ValueError, KeyError):
        _armed_view = None
    if _armed_view is None:
        try:
            view = _current_view()
        except Exception as exc:
            logger.warning("second-key: could not read config at load (%s)", type(exc).__name__)
            return
        if not tripwire.problems(view):
            _arm(view)
            _record("armed", how="first load", fingerprint=tripwire.fingerprint(view)[:16])


def _check_tripwire() -> list[str]:
    """Compare the approval settings with the armed ones; re-read only when config.yaml changed."""
    global _cfg_stamp, _tripped, _tripped_alerted
    if _armed_view is None or _tripped:
        return _tripped
    try:
        st = _config_path().stat()
        stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
    except OSError:
        stamp = None
    if stamp is not None and stamp == _cfg_stamp:
        return _tripped
    _cfg_stamp = stamp
    try:
        view = _current_view()
    except Exception as exc:
        view = None
        reasons = [f"could not read config.yaml ({type(exc).__name__})"]
    if view is not None:
        reasons = tripwire.changes(_armed_view, view) + tripwire.problems(view)
    if reasons:
        _tripped = reasons
        _record("tripwire", changed=reasons)
        _publish()
        _alert_approvers(reasons)
    return _tripped


def _alert_approvers(reasons: list[str]) -> None:
    global _tripped_alerted
    if _tripped_alerted:
        return
    _tripped_alerted = True
    text = ("second-key: Hermes' approval settings changed since they were armed ("
            + ", ".join(reasons)[:600] + "). The agent's tools are stopped until the profile owner "
            "runs /secondkey arm from a local Hermes session.")
    try:
        client, _ = _bot()
        for approver in _policy().approvers:
            try:
                client.call("sendMessage", {"chat_id": approver.telegram_id, "text": text})
            except TelegramError as exc:
                logger.info("second-key: tripwire alert to %s failed: %s", approver.name, exc)
    except Exception as exc:
        logger.warning("second-key: could not alert approvers (%s)", type(exc).__name__)


def _on_pre_tool_call(tool_name: str = "", args=None, **kwargs):
    """Two jobs. Stop every tool call while the approval settings differ from the armed ones, and
    refuse the direct commands an agent would use to switch approvals off or rewrite the SSH directory."""
    reasons = _check_tripwire()
    name = str(tool_name or "")
    if reasons:
        return {"action": "block", "message": (
            "second-key: Hermes' approval settings changed since they were armed ("
            + ", ".join(reasons)[:300] + "). Tools are stopped until the profile owner runs "
            "/secondkey arm from a local Hermes session.")}
    if name in _WRITE_TOOLS and isinstance(args, dict):
        target = str(args.get("path") or args.get("file_path") or "")
        if _under(target, Path.home() / ".ssh"):
            _record("tool_refused", tool=name, why="writes into the SSH directory")
            return {"action": "block", "message": (
                "second-key: writes into the SSH directory can make later ssh commands run anything, and Hermes "
                "asks for them in chat where the requester can answer. Refused.")}
    if name in _WRITE_TOOLS | _EXEC_TOOLS and _touches_own_data(name, args):
        _record("tool_refused", tool=name, why="touches second-key's own ledger or armed settings")
        return {"action": "block", "message": (
            "second-key: its ledger and armed settings are written only by second-key. "
            "Read the ledger with /secondkey ledger.")}
    if name in _EXEC_TOOLS and _TAMPER.search(_arg_text(args)):
        _record("tool_refused", tool=name, why="changes approval configuration")
        return {"action": "block", "message": (
            "second-key: this would change Hermes' approval settings or turn second-key off. "
            "Only the profile owner can do that, from outside the agent.")}
    return None


def _touches_own_data(name: str, args) -> bool:
    try:
        data_dir = _armed_file().parent
    except Exception:
        return False
    if name in _WRITE_TOOLS:  # file content may mention the names; only the target path and a V4A patch body count
        if not isinstance(args, dict):
            return False
        return (_under(str(args.get("path") or args.get("file_path") or ""), data_dir)
                or _names_own_data(str(args.get("patch") or ""), data_dir))
    return _names_own_data(_arg_text(args), data_dir)


def _on_vote(request_id: str, voter: str, choice: str) -> str:
    with _state_lock:
        ballot = _ballots.get(request_id)
    if ballot is None:
        # Closed, timed out or never ours: still record the tap so a late or stray vote is visible.
        _record("vote", request_id=request_id, voter=voter, choice=choice, result="unknown")
        return "unknown"
    result = ballot.vote(voter, choice)
    _record("vote", request_id=request_id, voter=voter, choice=choice, result=result)
    _publish()
    if result == "counted" or (result.startswith("ignored:") and result != "ignored:closed"):
        _refresh(_lives.get(request_id))
    return result


def _on_start(user_id: str, chat_id: str) -> None:
    try:
        client, _ = _bot()
        client.call("sendMessage", {"chat_id": chat_id, "text":
                    f"second-key: your Telegram id is {user_id}. Add it to the approvers roster "
                    "to receive approval requests here."})
    except TelegramError as exc:
        logger.info("second-key: enrollment reply failed: %s", exc)


# ---------------------------------------------------------------- transport

def present(request) -> Any:
    """Hermes runs this on a bare worker thread with none of the session's contextvars, so on a
    multiplexed gateway config reads land on the default profile and the bot token read raises.
    Run inside the context the pre_approval_request hook captured on the session thread."""
    with _state_lock:
        binding = _bindings.get(request.request_id)
    if binding is None:
        return _present(request)  # refuses: nobody can say who asked
    return binding[3].run(_present, request)


def _present(request) -> Any:
    """Hermes calls this on a worker thread with a redacted, immutable ApprovalRequest. It returns
    ``once`` only when the quorum is met by people other than the requester; anything else is deny."""
    with _state_lock:
        binding = _bindings.pop(request.request_id, None)
    deny = request.respond("deny")
    if "once" not in request.allowed_choices:
        return deny
    if binding is None:
        # Hermes fires pre_approval_request before every transport call. No binding means the
        # request reached us some other way, so nobody can say who asked: refuse.
        _record("refused", request_id=request.request_id, why="no requester binding for this request")
        return deny
    requester, requester_name, _, _, origin_chat = binding
    if requester.platform and requester.platform != "local" and not requester.user_id:
        _record("refused", request_id=request.request_id, platform=requester.platform,
                why="chat turn without a bound sender id")
        return deny
    if requester.platform == "telegram" and requester.user_id == TELEGRAM_ANONYMOUS_ADMIN:
        _record("refused", request_id=request.request_id, why="anonymous Telegram group admin")
        return deny
    if len(request.command) > MAX_COMMAND_CHARS:
        _record("refused", request_id=request.request_id, length=len(request.command),
                why="command too long to show approvers in full")
        return deny
    try:
        policy = _policy()
    except ValueError as exc:
        _record("refused", request_id=request.request_id, reason=f"bad config: {exc}")
        return deny

    wait = max(1.0, float(request.timeout_seconds) - 2.0)  # leave Hermes two seconds to act on the answer
    ballot = quorum.open_ballot(policy, request.request_id, request.command, requester, timeout=wait)
    base = dict(request_id=request.request_id, digest=request.digest, requester=requester.key or "unknown",
                required=ballot.required, reason=ballot.reason, pattern_key=request.pattern_key)
    note_chat = origin_chat if requester.platform == "telegram" and origin_chat else (
        requester.user_id if requester.platform == "telegram" else "")
    if ballot.impossible:
        _record("refused", **base, eligible=len(ballot.eligible),
                why="fewer eligible approvers than votes required")
        _tell_requester(note_chat, f"Denied: this command needs {ballot.required} approval(s) from people other "
                        f"than you, and only {len(ballot.eligible)} on the roster qualify.\n\n{request.command}")
        return deny

    try:
        client, poller = _bot()
    except TelegramError as exc:
        _record("refused", **base, why=str(exc))
        return deny

    live = _Live(request=request, requester=requester, name=requester_name, ballot=ballot,
                 deadline=time.monotonic() + wait)
    with _state_lock:
        _ballots[request.request_id] = ballot
        _lives[request.request_id] = live
    _publish()
    poller.ensure_running()
    sent: list[tuple[str, int]] = []
    for approver in ballot.eligible:
        try:
            message_id = client.send_ballot(approver.telegram_id, _ballot_text(live, "approver"), request.request_id)
            sent.append((approver.telegram_id, message_id))
            live.targets.append((approver.telegram_id, message_id, "approver"))
        except TelegramError as exc:
            _record("delivery_failed", request_id=request.request_id, approver=approver.name, why=str(exc))
    if note_chat:  # the requester sees why their own tap will not count, in the chat they asked from
        try:
            live.targets.append((note_chat, client.send_ballot(note_chat, _ballot_text(live, "requester"),
                                                                request.request_id), "requester"))
        except TelegramError as exc:
            _record("delivery_failed", request_id=request.request_id, approver="requester note", why=str(exc))
    if len(sent) < ballot.required:
        ballot.done.set()
    _record("presented", **base, delivered=len(sent), eligible=len(ballot.eligible))

    while not ballot.done.is_set():
        remaining = live.deadline - time.monotonic()
        if remaining <= 0:
            break
        ballot.done.wait(min(remaining, REFRESH_SECONDS))
        if not ballot.done.is_set() and live.deadline - time.monotonic() > 0:
            _refresh(live)
    with _state_lock:
        _ballots.pop(request.request_id, None)
    ballot.done.set()  # late taps are ignored from here on
    outcome = ballot.outcome
    entry = _record("decided", **base, outcome=outcome, yes=sorted(ballot.yes.values()), no=ballot.no,
                    ignored=ballot.ignored)
    if entry is None and outcome == "once":
        logger.error("second-key: approval %s met its quorum but the decision could not be recorded; denying",
                     request.request_id)
        outcome = "deny"  # no approval without a record of who gave it
    summary = _closing_text(request, ballot, outcome)
    if entry:
        summary += f"\n\nledger {entry['hash'][:16]}"
    with _state_lock:
        _lives.pop(request.request_id, None)
        _recent.append({**ballot.snapshot(), "command": request.command, "pattern_key": request.pattern_key,
                        "requester": {"name": requester_name, "platform": requester.platform or "local",
                                      "key": requester.key},
                        "outcome": outcome, "yes": sorted(ballot.yes.values()), "no": ballot.no,
                        "closed_at": time.time(), "ledger": entry["hash"] if entry else ""})
        del _recent[:-RECENT_KEPT]
    _publish()
    # Closing the DMs must not push the answer past Hermes' deadline: do it off this thread.
    threading.Thread(target=_close_all, args=(client, live, summary), name="second-key-close",
                     daemon=True).start()
    return request.respond(outcome)


def _tell_requester(chat_id: str, text: str) -> None:
    if not chat_id:
        return
    try:
        client, _ = _bot()
        client.notify(chat_id, text)
    except TelegramError as exc:
        logger.info("second-key: could not tell the requester: %s", exc)


def _close_all(client, live: _Live, summary: str) -> None:
    with live.lock:  # waits for a refresh in flight, so the closing text is always the last edit
        live.closed = True
    for chat_id, message_id, _ in live.targets:
        client.close_ballot(chat_id, message_id, summary)


def _refresh(live: _Live | None) -> None:
    """Rewrite every open copy of a ballot with its current votes and remaining time."""
    if live is None:
        return
    with live.lock:
        if live.closed:
            return
        client, _ = _bot()
        for chat_id, message_id, audience in list(live.targets):
            client.edit_ballot(chat_id, message_id, _ballot_text(live, audience), live.request.request_id)


def _clock(seconds: float) -> str:
    seconds = max(0, int(seconds))
    return f"{seconds // 60}m {seconds % 60:02d}s" if seconds >= 60 else f"{seconds}s"


def _ballot_text(live: _Live, audience: str) -> str:
    request, requester, ballot = live.request, live.requester, live.ballot
    who = (f"{live.name} ({requester.platform} id {requester.user_id})" if requester.known
           else "unknown requester")
    risk = {"critical": f"CRITICAL ({request.pattern_key or 'critical pattern'})",
            "unknown requester": "requester unknown"}.get(ballot.tier, "standard")
    others = ", ".join(a.name for a in ballot.eligible)
    lines = ["Hermes wants to run a command that needs approval.", f"Risk: {risk}", f"Asked by: {who}",
             f"Reason: {request.description}", "", request.command, ""]
    if audience == "requester":
        lines += [f"{live.name}: you asked for this command, so your tap here is Not counted. "
                  f"{ballot.required} approval(s) are needed from other people: {others}.", ""]
    else:
        lines += [f"Needs {ballot.required} approval(s) from people other than the requester ({ballot.reason}).", ""]
    lines += [f"{ballot.squares()}  {ballot.progress()}"]
    waiting = ballot.waiting_on()
    if waiting:
        lines.append(f"Waiting on: {', '.join(waiting)}")
    if ballot.not_counted:
        lines.append("Not counted: " + ", ".join(
            f"{n['name']} ({'requester' if n['why'] == 'requester' else 'not an approver'})"
            for n in ballot.not_counted))
    lines.append(f"Time left: {_clock(live.deadline - time.monotonic())}. No answer means deny.")
    return "\n".join(lines)


def _closing_text(request, ballot: quorum.Ballot, outcome: str) -> str:
    if outcome == "once":
        verdict = f"Approved once by {', '.join(sorted(ballot.yes.values()))}."
    elif ballot.no:
        verdict = f"Denied by {ballot.no}."
    elif len(ballot.yes) >= ballot.required:
        verdict = "Denied: the approvals could not be written to the ledger."
    else:
        verdict = f"Denied: {len(ballot.yes)} of {ballot.required} approval(s) before the deadline."
    return f"{verdict}\n{ballot.squares()}  {ballot.progress()}\n\n{request.command}"


# ---------------------------------------------------------------- command

def _local_identity() -> str:
    """The id Hermes binds for a local session, in the form an approver lists under ``aliases``.
    Empty when the call comes from a chat."""
    platform = _session("HERMES_SESSION_PLATFORM").lower()
    if platform and platform not in quorum.LOCAL_PLATFORMS:
        return ""
    actor = _session("HERMES_SESSION_ACTOR_ID") or _session("HERMES_SESSION_USER_ID")
    if actor:
        return f"{platform or 'local'}:{actor}"
    uid = getattr(os, "getuid", None)
    return f"local:uid:{uid()}" if uid else ""


def _cmd_secondkey(args: str = "", **kwargs) -> str:
    global _enroll_until
    sub = (args or "").strip().split()
    action = sub[0] if sub else "status"
    if action == "ledger":
        n = int(sub[1]) if len(sub) > 1 and sub[1].isdigit() else 10
        entries = _get_ledger().tail(n)
        ok, bad = _get_ledger().verify()
        head = f"ledger chain {'intact' if ok else f'BROKEN at line {bad}'}"
        return "\n".join([head] + [" ".join(filter(None, (e["ts"], e["event"], e.get("outcome") or e.get("result"),
                                                           e["hash"][:16]))) for e in entries])
    if action == "enroll":
        try:
            _, poller = _bot()
        except TelegramError as exc:
            return f"second-key: cannot enroll: {exc}"
        _enroll_until = time.monotonic() + ENROLL_SECONDS
        poller.ensure_running()
        return (f"second-key: reading the bot for {ENROLL_SECONDS // 60} minutes. Each approver sends /start "
                "to the bot in a DM and gets their Telegram id back.")
    if action == "arm":
        platform = str(kwargs.get("platform") or _session("HERMES_SESSION_PLATFORM") or "").lower()
        if platform not in _LOCAL_SURFACES:
            return "second-key: /secondkey arm only works from a local Hermes session (CLI, TUI or Desktop)."
        try:
            _policy()
            view = _current_view()
        except Exception as exc:
            return f"second-key: not armed: {exc}"
        problems = tripwire.problems(view)
        if problems:
            return "second-key: not armed:\n" + "\n".join(f"  - {p}" for p in problems)
        _arm(view)
        fp = tripwire.fingerprint(view)[:16]
        _record("armed", how="/secondkey arm", fingerprint=fp)
        return f"second-key armed (settings fingerprint {fp}). Tools are running again."
    try:
        policy = _policy()
    except ValueError as exc:
        return f"second-key is NOT armed: {exc}"
    lines = []
    reasons = _check_tripwire()
    if _armed_view is None:
        try:
            problems = tripwire.problems(_current_view())
        except Exception as exc:
            problems = [f"could not read Hermes config ({type(exc).__name__})"]
        lines.append("NOT ARMED:" if problems else "not armed yet: run /secondkey arm from a local session")
        lines.extend(f"  - {p}" for p in problems)
    elif reasons:
        lines.append("TRIPPED, agent tools stopped:")
        lines.extend(f"  - {r}" for r in reasons)
    else:
        lines.append(f"ARMED (settings fingerprint {tripwire.fingerprint(_armed_view)[:16]})")
    lines.extend(quorum.describe(policy))
    identity = _local_identity()
    if identity:
        lines.append(f"this local session is {identity}: list it under your approver entry's aliases "
                     "to exclude yourself as the requester")
    from agent.secret_scope import get_secret
    lines.append(f"bot token: {'set' if get_secret(TOKEN_ENV) else 'MISSING'} ({TOKEN_ENV})")
    lines.append(f"select it with security.approval.transport: {TRANSPORT}")
    return "\n".join(lines)


def register(ctx) -> None:
    global _ctx
    _ctx = ctx
    ctx.register_hook("pre_approval_request", _on_pre_approval_request)
    ctx.register_hook("pre_gateway_dispatch", _on_pre_gateway_dispatch)
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    _load_armed()
    ctx.register_approval_transport(TRANSPORT, present)
    ctx.register_command("secondkey", _cmd_secondkey,
                         description="second-key status, `enroll` to collect approver ids, `ledger [n]` for recent decisions",
                         args_hint="[status|enroll|arm|ledger [n]]")
    ctx.on_unload(_unload)


def _unload() -> None:
    """Stop the Telegram reader so a reloaded copy of the plugin is the only one polling."""
    if _poller is not None:
        _poller.stop()
