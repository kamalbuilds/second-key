"""Telegram Bot API delivery for second-key: DM each approver, collect button taps.

stdlib only (urllib), so the plugin adds no dependency. One long-poll thread per process reads
``getUpdates`` while it is wanted (a ballot is open, or enrollment is on) and hands each button tap
to the ballot it belongs to. second-key uses its own bot,
never the gateway's: two pollers on one token make Telegram answer 409 Conflict.

The voter's identity is ``callback_query.from.id``, which Telegram sets. Button data carries only
the request id and the choice, so a forwarded or copied message cannot vote as someone else.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from typing import Callable, Optional

logger = logging.getLogger(__name__)

API = "https://api.telegram.org"
_TIMEOUT = 35  # long-poll is 25s; leave room for the network


class TelegramError(RuntimeError):
    pass


class BotClient:
    def __init__(self, token: str, *, base_url: str = API, opener: Optional[urllib.request.OpenerDirector] = None):
        if not token or ":" not in token:
            raise TelegramError("bot token missing or malformed")
        self._base = f"{base_url.rstrip('/')}/bot{token}"
        # No redirects: a redirect would resend the token-bearing URL somewhere else.
        self._opener = opener or urllib.request.build_opener(_NoRedirect)

    def call(self, method: str, payload: dict, timeout: float = 15) -> dict:
        req = urllib.request.Request(f"{self._base}/{method}", data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            # The URL holds the token, so never log it; Telegram's description is safe.
            try:
                desc = json.loads(exc.read().decode()).get("description", "")
            except (ValueError, OSError):
                desc = ""
            raise TelegramError(f"{method} failed: HTTP {exc.code} {desc}".strip()) from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise TelegramError(f"{method} failed: {type(exc).__name__}") from None
        if not body.get("ok"):
            raise TelegramError(f"{method} failed: {body.get('description', 'not ok')}")
        return body.get("result") or {}

    @staticmethod
    def _markup(request_id: str) -> dict:
        return {"inline_keyboard": [[
            {"text": "Approve once", "callback_data": f"sk|{request_id}|once"},
            {"text": "Deny", "callback_data": f"sk|{request_id}|deny"},
        ]]}

    def send_ballot(self, chat_id: str, text: str, request_id: str) -> int:
        msg = self.call("sendMessage", {"chat_id": chat_id, "text": text, "reply_markup": self._markup(request_id),
                                        "disable_web_page_preview": True})
        return int(msg.get("message_id", 0))

    def notify(self, chat_id: str, text: str) -> None:
        self.call("sendMessage", {"chat_id": chat_id, "text": text, "disable_web_page_preview": True})

    def edit_ballot(self, chat_id: str, message_id: int, text: str, request_id: str) -> None:
        """Rewrite an open ballot in place. editMessageText drops the buttons unless they are sent again."""
        try:
            self.call("editMessageText", {"chat_id": chat_id, "message_id": message_id, "text": text,
                                          "reply_markup": self._markup(request_id), "disable_web_page_preview": True})
        except TelegramError as exc:
            logger.info("second-key: could not refresh ballot message: %s", exc)

    def close_ballot(self, chat_id: str, message_id: int, text: str) -> None:
        try:
            self.call("editMessageText", {"chat_id": chat_id, "message_id": message_id, "text": text})
        except TelegramError as exc:
            logger.info("second-key: could not update ballot message: %s", exc)

    def answer(self, callback_id: str, text: str, alert: bool = False) -> None:
        try:
            self.call("answerCallbackQuery", {"callback_query_id": callback_id, "text": text[:190],
                                              "show_alert": alert})
        except TelegramError as exc:
            logger.info("second-key: answerCallbackQuery failed: %s", exc)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


VoteHandler = Callable[[str, str, str], str]  # (request_id, voter_telegram_id, choice) -> result


class Poller:
    """Single getUpdates loop. ``on_vote`` decides; the poller only parses and acknowledges."""

    def __init__(self, client: BotClient, on_vote: VoteHandler, on_start: Callable[[str, str], None] | None = None,
                 wanted: Callable[[], bool] | None = None):
        self._client = client
        self._wanted = wanted or (lambda: True)
        self._on_vote = on_vote
        self._on_start = on_start
        self._offset = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def ensure_running(self) -> None:
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._stop.clear()
                self._thread = threading.Thread(target=self._run, name="second-key-telegram", daemon=True)
                self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        backoff = 1.0
        while not self._stop.is_set():
            with self._lock:  # decided under the lock ensure_running takes, so a new ballot is never missed
                if not self._wanted():
                    self._thread = None
                    return
            try:
                updates = self._client.call(
                    "getUpdates",
                    {"offset": self._offset, "timeout": 25, "allowed_updates": ["callback_query", "message"]},
                    timeout=_TIMEOUT)
                backoff = 1.0
            except TelegramError as exc:
                if "409" in str(exc):
                    logger.error("second-key: another process is reading this bot's updates (409 Conflict). "
                                 "Give second-key its own bot token; votes may be lost until then.")
                else:
                    logger.warning("second-key: %s; retrying in %.0fs", exc, backoff)
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 30.0)
                continue
            for update in updates if isinstance(updates, list) else []:
                self._offset = max(self._offset, int(update.get("update_id", 0)) + 1)
                try:
                    self.handle(update)
                except Exception:
                    logger.exception("second-key: failed to handle a Telegram update")

    def handle(self, update: dict) -> None:
        cq = update.get("callback_query")
        if cq:
            data = str(cq.get("data") or "")
            voter = str((cq.get("from") or {}).get("id") or "")
            parts = data.split("|")
            if len(parts) != 3 or parts[0] != "sk" or not voter:
                self._client.answer(str(cq.get("id", "")), "Not a second-key button.")
                return
            result = self._on_vote(parts[1], voter, parts[2])
            reply = _VOTE_REPLIES.get(result) or _VOTE_REPLIES.get(result.split(":")[0], result)
            self._client.answer(str(cq.get("id", "")), reply, alert=result.startswith("ignored"))
            return
        msg = update.get("message") or {}
        text = str(msg.get("text") or "")
        if text.startswith("/start") and self._on_start and (msg.get("chat") or {}).get("type") == "private":
            self._on_start(str((msg.get("from") or {}).get("id") or ""), str(msg["chat"]["id"]))


_VOTE_REPLIES = {
    "counted": "Vote counted. Waiting for another approver.",
    "approved": "Approved. The command can run once.",
    "denied": "Denied. The command will not run.",
    "ignored:requester": "Not counted: you asked for this command, so you cannot approve it. Other approvers must.",
    "ignored": "Not counted: you cannot vote on this request.",
    "unknown": "This request has already closed.",
}
