"""second-key: the person who asks for a dangerous command can never be the one who approves it.

Selected with ``security.approval.transport: secondkey``. Each approval Hermes raises is sent by
Telegram DM to the approvers on a roster. The requester's own vote is never counted, critical
commands need more yes votes, and a request whose requester is unknown needs more still. Any
error, timeout or missing configuration is a deny; Hermes enforces the deny host-side.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from . import quorum
from .ledger import Ledger
from .telegram import BotClient, Poller, TelegramError

logger = logging.getLogger(__name__)

TRANSPORT = "secondkey"
TOKEN_ENV = "SECONDKEY_TELEGRAM_BOT_TOKEN"
_BINDING_TTL = 900.0  # an approval is presented within seconds of its hook; stale bindings expire

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
    except OSError as exc:
        logger.warning("second-key: ledger write failed: %s", exc)


def _expire_bindings(now: float) -> None:
    for rid in [r for r, (_, _, t) in _bindings.items() if now - t > _BINDING_TTL]:
        _bindings.pop(rid, None)


# ---------------------------------------------------------------- hooks

def _on_pre_approval_request(request_id: str = "", **kwargs) -> None:
    """Runs on the agent's own thread, where the turn's session identity is bound. The transport
    worker that Hermes starts next is a fresh thread without it, so bind the requester here."""
    if not request_id:
        return
    requester = quorum.Requester(platform=_session("HERMES_SESSION_PLATFORM").lower(),
                                 user_id=_session("HERMES_SESSION_USER_ID"))
    name = _session("HERMES_SESSION_USER_NAME") or requester.user_id
    with _state_lock:
        now = time.monotonic()
        _expire_bindings(now)
        _bindings[request_id] = (requester, name, now)


def _on_pre_gateway_dispatch(event=None, **kwargs):
    """Close the /yolo bypass: YOLO skips approvals entirely, so only roster members may turn it on
    from a chat. Everyone else's /yolo is dropped before it reaches the agent."""
    text = str(getattr(event, "text", "") or "").strip().lower()
    if not text.startswith("/yolo"):
        return None
    src = getattr(event, "source", None)
    platform = getattr(getattr(src, "platform", None), "value", getattr(src, "platform", "")) or ""
    user_id = str(getattr(src, "user_id", "") or "")
    try:
        allowed = quorum.is_on_roster(_policy(), str(platform).lower(), user_id)
    except ValueError:
        allowed = False
    if allowed:
        return None
    _record("yolo_refused", platform=str(platform), user_id=user_id)
    return {"action": "skip", "reason": "second-key: /yolo is limited to approvers"}


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
        requester, requester_name, _ = _bindings.pop(request.request_id, (quorum.Requester(), "", 0.0))
    deny = request.respond("deny")
    if "once" not in request.allowed_choices:
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
    summary = _closing_text(request, ballot, outcome)
    for chat_id, message_id in sent:
        client.close_ballot(chat_id, message_id, summary)
    _record("decided", **base, outcome=outcome, yes=sorted(ballot.yes.values()), no=ballot.no,
            ignored=ballot.ignored)
    return request.respond(outcome)


def _ballot_text(request, requester: quorum.Requester, requester_name: str, ballot: quorum.Ballot) -> str:
    who = f"{requester_name} ({requester.platform})" if requester.known else "unknown requester"
    lines = [
        "Hermes wants to run a command that needs approval.",
        f"Asked by: {who}",
        f"Reason: {request.description}",
        "",
        request.command[:1500],
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
    return f"{verdict}\n\n{request.command[:800]}"


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
    lines = list(quorum.describe(policy))
    from agent.secret_scope import get_secret
    lines.append(f"bot token: {'set' if get_secret(TOKEN_ENV) else 'MISSING'} ({TOKEN_ENV})")
    lines.append(f"select it with security.approval.transport: {TRANSPORT}")
    return "\n".join(lines)


def register(ctx) -> None:
    global _ctx
    _ctx = ctx
    ctx.register_hook("pre_approval_request", _on_pre_approval_request)
    ctx.register_hook("pre_gateway_dispatch", _on_pre_gateway_dispatch)
    ctx.register_approval_transport(TRANSPORT, present)
    ctx.register_command("secondkey", _cmd_secondkey,
                         description="second-key status, or `ledger [n]` for recent decisions",
                         args_hint="[status|ledger [n]]")
