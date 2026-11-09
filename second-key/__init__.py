"""second-key: the person who asks for a dangerous command can never be the one who approves it.

Selected with ``security.approval.transport: secondkey``. Dangerous terminal commands and
execute_code scripts that Hermes routes to its approval transport are sent by Telegram DM to the
approvers on a roster. The requester's own vote is never counted, critical commands need more yes
votes, and any error, timeout, unidentified sender or missing configuration is a deny, which Hermes
enforces host-side. Chat commands and tool calls that would switch approvals off are refused.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from typing import Any

from . import quorum
from .ledger import Ledger
from .telegram import BotClient, Poller, TelegramError

logger = logging.getLogger(__name__)

TRANSPORT = "secondkey"
TOKEN_ENV = "SECONDKEY_TELEGRAM_BOT_TOKEN"
_BINDING_TTL = 900.0
MAX_COMMAND_CHARS = 3000  # Telegram messages cap at 4096; approvers must see the whole command
_GATED_COMMANDS = frozenset({"yolo", "approvals"})
TELEGRAM_ANONYMOUS_ADMIN = "1087968824"  # GroupAnonymousBot: an anonymous group admin, not a person  # an approval is presented within seconds of its hook; stale bindings expire

_ctx: Any = None
_bindings: dict[str, tuple[quorum.Requester, str, float]] = {}
_ballots: dict[str, quorum.Ballot] = {}
_state_lock = threading.Lock()
_client: BotClient | None = None
_poller: Poller | None = None
_ledger: Ledger | None = None


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
            _poller = Poller(_client, _on_vote, _on_start)
        _poller.ensure_running()
        return _client, _poller


def _get_ledger() -> Ledger:
    global _ledger
    if _ledger is None:
        from plugins.plugin_storage import plugin_data_dir
        _ledger = Ledger(plugin_data_dir("second-key") / "ledger.jsonl")
    return _ledger


def _record(event: str, **fields) -> None:
    try:
        _get_ledger().append(event, **fields)
    except Exception as exc:  # a broken ledger must never decide an approval
        logger.warning("second-key: ledger write failed (%s)", type(exc).__name__)


def _expire_bindings(now: float) -> None:
    for rid in [r for r, (_, _, t) in _bindings.items() if now - t > _BINDING_TTL]:
        _bindings.pop(rid, None)


# ---------------------------------------------------------------- hooks

def _on_pre_approval_request(request_id: str = "", **kwargs) -> None:
    """Runs on the agent's own thread, where the turn's session identity is bound. The transport
    worker that Hermes starts next is a fresh thread without it, so bind the requester here."""
    if not request_id:
        return
    # ACTOR_ID is the person whose message started this turn; in a shared (observe-mode) group
    # USER_ID is empty and only ACTOR_ID carries the sender.
    requester = quorum.Requester(platform=_session("HERMES_SESSION_PLATFORM").lower(),
                                 user_id=_session("HERMES_SESSION_ACTOR_ID") or _session("HERMES_SESSION_USER_ID"))
    name = (_session("HERMES_SESSION_ACTOR_NAME") or _session("HERMES_SESSION_USER_NAME")
            or requester.user_id)
    with _state_lock:
        now = time.monotonic()
        _expire_bindings(now)
        _bindings[request_id] = (requester, name, now)


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
    if command not in _GATED_COMMANDS:
        return None
    src = getattr(event, "source", None)
    platform = getattr(getattr(src, "platform", None), "value", getattr(src, "platform", "")) or ""
    _record("command_refused", command=command, platform=str(platform),
            user_id=str(getattr(src, "user_id", "") or ""))
    return {"action": "skip", "reason": f"second-key: /{command} is not available from chats"}


_TAMPER_PARTS = (
    r"hermes\S*\s+(config\s+(set|unset|edit|migrate)|plugins?\s+(disable|remove|uninstall|update|install)|approvals?\b|auth\b)",
    r"config\.ya?ml",
    r"\.hermes/\.env\b",
    r"security\.approval",
    r"approvals\.mode",
    r"second-?key",
)
_TAMPER = re.compile("|".join(_TAMPER_PARTS), re.IGNORECASE)
_SSH_PATH = re.compile(r"(^|[\s/~])\.ssh(/|\b)")
_WRITE_TOOLS = {"write_file", "patch", "edit_file", "apply_patch", "str_replace_editor", "create_file"}
_EXEC_TOOLS = {"terminal", "execute_code", "shell", "bash", "process"}


def _arg_text(args) -> str:
    if isinstance(args, dict):
        return " ".join(str(v) for v in args.values() if isinstance(v, (str, int, float)))
    return str(args or "")


def _on_pre_tool_call(tool_name: str = "", args=None, **kwargs):
    """Refuse tool calls that would change who approves, or switch approvals off. The approval
    system cannot protect itself if the agent may rewrite its configuration unprompted."""
    name = str(tool_name or "")
    if name not in _EXEC_TOOLS and name not in _WRITE_TOOLS:
        return None
    text = _arg_text(args)
    if name in _WRITE_TOOLS and _SSH_PATH.search(text):
        _record("tool_refused", tool=name, why="writes under ~/.ssh")
        return {"action": "block", "message": (
            "second-key: writes under ~/.ssh can make later ssh commands run anything, and Hermes "
            "asks for them in chat where the requester can answer. Refused.")}
    if not _TAMPER.search(text):
        return None
    _record("tool_refused", tool=name, why="touches approval configuration")
    return {"action": "block", "message": (
        "second-key: this would change Hermes' approval settings or the approver roster. "
        "Only the profile owner can do that, from outside the agent.")}


def _arming_problems() -> list[str]:
    """Settings under which second-key is installed but not actually deciding approvals."""
    from hermes_cli.config import load_config_readonly
    cfg = load_config_readonly() or {}
    security = (cfg.get("security") or {}).get("approval") or {}
    problems = []
    if str(security.get("transport") or "builtin").lower() != TRANSPORT:
        problems.append(f"security.approval.transport is {security.get('transport') or 'builtin'!r}, not {TRANSPORT!r}")
    if str(security.get("transport_fallback") or "").lower() == "builtin":
        problems.append("transport_fallback: builtin lets a failed transport fall back to the chat prompt")
    mode = str((cfg.get("approvals") or {}).get("mode") or "").lower()
    if mode in {"off", "smart"}:
        problems.append(f"approvals.mode is {mode!r}: Hermes decides some commands without asking")
    if str((cfg.get("plugins") or {}).get("isolation") or "").lower() == "host":
        problems.append("plugins.isolation: host is set; approval transports need in-process plugins")
    return problems


def _on_vote(request_id: str, voter: str, choice: str) -> str:
    with _state_lock:
        ballot = _ballots.get(request_id)
    if ballot is None:
        return "unknown"
    result = ballot.vote(voter, choice)
    _record("vote", request_id=request_id, voter=voter, choice=choice, result=result)
    return result


def _on_start(user_id: str, chat_id: str) -> None:
    _record("enrolled", telegram_id=user_id)
    try:
        client, _ = _bot()
        client.call("sendMessage", {"chat_id": chat_id, "text":
                    f"second-key: your Telegram id is {user_id}. Add it to the approvers roster "
                    "to receive approval requests here."})
    except TelegramError as exc:
        logger.info("second-key: enrollment reply failed: %s", exc)


# ---------------------------------------------------------------- transport

def present(request) -> Any:
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
    requester, requester_name, _ = binding
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

    ballot = quorum.open_ballot(policy, request.request_id, request.command, requester)
    base = dict(request_id=request.request_id, digest=request.digest, requester=requester.key or "unknown",
                required=ballot.required, reason=ballot.reason, pattern_key=request.pattern_key)
    if ballot.impossible:
        _record("refused", **base, eligible=len(ballot.eligible),
                why="fewer eligible approvers than votes required")
        return deny

    try:
        client, _ = _bot()
    except TelegramError as exc:
        _record("refused", **base, why=str(exc))
        return deny

    with _state_lock:
        _ballots[request.request_id] = ballot
    text = _ballot_text(request, requester, requester_name, ballot)
    sent: list[tuple[str, int]] = []
    for approver in ballot.eligible:
        try:
            sent.append((approver.telegram_id, client.send_ballot(approver.telegram_id, text, request.request_id)))
        except TelegramError as exc:
            _record("delivery_failed", request_id=request.request_id, approver=approver.name, why=str(exc))
    if len(sent) < ballot.required:
        ballot.done.set()
    _record("presented", **base, delivered=len(sent), eligible=len(ballot.eligible))

    deadline = time.monotonic() + max(1.0, float(request.timeout_seconds) - 2.0)
    ballot.done.wait(max(0.0, deadline - time.monotonic()))
    with _state_lock:
        _ballots.pop(request.request_id, None)
    ballot.done.set()  # late taps are ignored from here on
    outcome = ballot.outcome
    _record("decided", **base, outcome=outcome, yes=sorted(ballot.yes.values()), no=ballot.no,
            ignored=ballot.ignored)
    summary = _closing_text(request, ballot, outcome)
    # Closing the DMs must not push the answer past Hermes' deadline: do it off this thread.
    threading.Thread(target=_close_all, args=(client, sent, summary), name="second-key-close",
                     daemon=True).start()
    return request.respond(outcome)


def _close_all(client, sent, summary) -> None:
    for chat_id, message_id in sent:
        client.close_ballot(chat_id, message_id, summary)


def _ballot_text(request, requester: quorum.Requester, requester_name: str, ballot: quorum.Ballot) -> str:
    who = f"{requester_name} ({requester.platform})" if requester.known else "unknown requester"
    lines = [
        "Hermes wants to run a command that needs approval.",
        f"Asked by: {who}",
        f"Reason: {request.description}",
        "",
        request.command,
        "",
        f"Needs {ballot.required} approval(s) from people other than the requester ({ballot.reason}).",
        f"No answer within {int(request.timeout_seconds)}s means deny.",
    ]
    return "\n".join(lines)


def _closing_text(request, ballot: quorum.Ballot, outcome: str) -> str:
    if outcome == "once":
        verdict = f"Approved once by {', '.join(sorted(ballot.yes.values()))}."
    elif ballot.no:
        verdict = f"Denied by {ballot.no}."
    else:
        verdict = f"Denied: {len(ballot.yes)} of {ballot.required} approval(s) before the deadline."
    return f"{verdict}\n\n{request.command}"


# ---------------------------------------------------------------- command

def _cmd_secondkey(args: str = "", **kwargs) -> str:
    sub = (args or "").strip().split()
    action = sub[0] if sub else "status"
    if action == "ledger":
        n = int(sub[1]) if len(sub) > 1 and sub[1].isdigit() else 10
        entries = _get_ledger().tail(n)
        ok, bad = _get_ledger().verify()
        head = f"ledger chain {'intact' if ok else f'BROKEN at line {bad}'}"
        return "\n".join([head] + [f"{e['ts']} {e['event']} {e.get('outcome') or e.get('result') or ''}".rstrip()
                                   for e in entries])
    try:
        policy = _policy()
    except ValueError as exc:
        return f"second-key is NOT armed: {exc}"
    lines = []
    try:
        problems = _arming_problems()
    except Exception as exc:
        problems = [f"could not read Hermes config ({type(exc).__name__})"]
    lines.append("ARMED" if not problems else "NOT ARMED:")
    lines.extend(f"  - {p}" for p in problems)
    lines.extend(quorum.describe(policy))
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
    ctx.register_approval_transport(TRANSPORT, present)
    ctx.register_command("secondkey", _cmd_secondkey,
                         description="second-key status, or `ledger [n]` for recent decisions",
                         args_hint="[status|ledger [n]]")
