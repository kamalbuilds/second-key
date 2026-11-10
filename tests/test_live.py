"""The live ballot: DMs rewritten in place as votes arrive, the requester's note, and the pane's state file."""
import importlib.util
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from gateway.session_context import clear_session_vars, reset_session_vars, set_session_vars
from hermes_cli.approval_transport import ApprovalRequest

ROOT = Path(__file__).resolve().parents[1] / "second-key"
spec = importlib.util.spec_from_file_location("second_key_live", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
from second_key_live.telegram import BotClient, Poller, TelegramError  # noqa: E402


def request(command="rm -rf /srv/builds/staging", timeout=30):
    return ApprovalRequest.create(command=command, description="recursive delete", pattern_key="recursive delete",
                                  pattern_keys=("recursive delete",), session_key="k", surface="gateway",
                                  allow_session=False, allow_permanent=False, timeout_seconds=timeout)


class FakeBot:
    """Records every call a ballot makes. ``fail_chat`` makes sends to that chat raise, like a bot that is not a member."""

    def __init__(self, fail_chat=None):
        self.sent, self.edits, self.closed, self.notes = [], [], [], []
        self.fail_chat, self.edit_gate = fail_chat, None
        self.lock = threading.Lock()

    def send_ballot(self, chat_id, text, request_id):
        if chat_id == self.fail_chat:
            raise TelegramError("sendMessage failed: bot is not a member")
        with self.lock:
            self.sent.append((chat_id, text, request_id))
            return len(self.sent)

    def edit_ballot(self, chat_id, message_id, text, request_id):
        if self.edit_gate:
            self.edit_gate.wait(5)
        with self.lock:
            self.edits.append((chat_id, message_id, text, request_id))

    def close_ballot(self, chat_id, message_id, text):
        with self.lock:
            self.closed.append((chat_id, message_id, text))

    def notify(self, chat_id, text):
        self.notes.append((chat_id, text))


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)
        self.saved = (plugin._policy, plugin._get_ledger, plugin._bot, plugin._state_file, plugin.REFRESH_SECONDS)
        plugin._policy = lambda: plugin.quorum.parse_policy({"approvers": [
            {"name": "Priya", "telegram_id": "111"}, {"name": "Dev", "telegram_id": "222"},
            {"name": "Sam", "telegram_id": "333"}], "critical_patterns": [r"rm\s+-rf"]})
        plugin._get_ledger = lambda: plugin.Ledger(self.dir / "ledger.jsonl")
        plugin._state_file = lambda: self.dir / "state.json"
        self.bot = FakeBot()
        plugin._bot = lambda: (self.bot, SimpleNamespace(ensure_running=lambda: None))
        plugin._recent.clear()

    def tearDown(self):
        plugin._policy, plugin._get_ledger, plugin._bot, plugin._state_file, plugin.REFRESH_SECONDS = self.saved
        plugin._bindings.clear()
        plugin._ballots.clear()
        plugin._lives.clear()
        plugin._recent.clear()
        reset_session_vars()
        self.temp.cleanup()

    def start(self, req, platform="telegram", actor_id="111", chat_id="-100", sends=3):
        tokens = set_session_vars(platform=platform, actor_id=actor_id, actor_name="Priya", chat_id=chat_id)
        try:
            plugin._on_pre_approval_request(request_id=req.request_id)
        finally:
            clear_session_vars(tokens)
        out = []
        worker = threading.Thread(target=lambda: out.append(plugin.present(req)))
        worker.start()
        self.until(lambda: len(self.bot.sent) >= sends)
        return worker, out

    def until(self, check, seconds=5):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if check():
                return
            time.sleep(0.02)
        self.fail("timed out waiting")

    def state(self):
        return json.loads((self.dir / "state.json").read_text())


class ProgressEditTests(Base):
    def test_each_vote_rewrites_every_dm_in_place_with_progress_risk_and_time(self):
        req = request()
        worker, out = self.start(req)
        self.assertEqual(plugin._on_vote(req.request_id, "222", "once"), "counted")
        self.assertEqual(len(self.bot.edits), 3, "two approver DMs and the requester's copy")
        text = self.bot.edits[0][2]
        for want in ("Risk: CRITICAL (recursive delete)", "■□  1 of 2 approved: Dev", "Waiting on: Sam", "Time left:"):
            self.assertIn(want, text)
        self.assertEqual({e[3] for e in self.bot.edits}, {req.request_id})
        self.assertEqual(plugin._on_vote(req.request_id, "333", "once"), "approved")
        worker.join(5)
        self.assertEqual(out[0].choice, "once")

    def test_closing_edit_keeps_the_ledger_hash_and_the_filled_squares(self):
        req = request()
        worker, _ = self.start(req)
        plugin._on_vote(req.request_id, "222", "once")
        plugin._on_vote(req.request_id, "333", "once")
        worker.join(5)
        self.until(lambda: len(self.bot.closed) == 3)
        decided = [e for e in plugin._get_ledger().entries() if e["event"] == "decided"][-1]
        for _, _, text in self.bot.closed:
            self.assertIn("Approved once by Dev, Sam.", text)
            self.assertIn("■■  2 of 2 approved: Dev, Sam", text)
            self.assertIn(f"ledger {decided['hash'][:16]}", text)

    def test_standard_risk_is_labelled_standard(self):
        req = request("ls /srv")
        worker, _ = self.start(req)
        self.assertIn("Risk: standard", self.bot.sent[0][1])
        plugin._on_vote(req.request_id, "222", "once")
        worker.join(5)

    def test_the_remaining_time_is_rewritten_while_nobody_votes(self):
        plugin.REFRESH_SECONDS = 0.05
        req = request(timeout=3)
        worker, out = self.start(req)
        worker.join(5)
        self.assertEqual(out[0].choice, "deny")
        self.assertGreaterEqual(len(self.bot.edits), 3 * 2, "every copy was refreshed more than once")
        self.until(lambda: len(self.bot.closed) == 3)
        self.assertIn("Denied: 0 of 2 approval(s) before the deadline.", self.bot.closed[0][2])

    def test_a_refresh_after_the_ballot_closed_edits_nothing(self):
        req = request()
        worker, _ = self.start(req)
        live = plugin._lives[req.request_id]
        plugin._on_vote(req.request_id, "222", "once")
        plugin._on_vote(req.request_id, "333", "once")
        worker.join(5)
        self.until(lambda: len(self.bot.closed) == 3)
        before = len(self.bot.edits)
        plugin._refresh(live)
        self.assertEqual(len(self.bot.edits), before)

    def test_the_closing_edit_waits_for_a_refresh_in_flight(self):
        """A slow refresh must never land after the closing text and overwrite it."""
        req = request()
        worker, _ = self.start(req)
        live = plugin._lives[req.request_id]
        self.bot.edit_gate = threading.Event()
        refresher = threading.Thread(target=plugin._refresh, args=(live,))
        refresher.start()
        self.until(lambda: live.lock.locked())
        closer = threading.Thread(target=plugin._close_all, args=(self.bot, live, "final"))
        closer.start()
        time.sleep(0.2)
        self.assertEqual(self.bot.closed, [], "closing went ahead of the refresh")
        self.bot.edit_gate.set()
        refresher.join(5)
        closer.join(5)
        self.assertEqual(len(self.bot.closed), 3)
        plugin._on_vote(req.request_id, "222", "deny")
        worker.join(5)


class RequesterNoteTests(Base):
    def test_requester_gets_a_note_in_the_chat_they_asked_from(self):
        req = request()
        worker, _ = self.start(req)
        chats = [s[0] for s in self.bot.sent]
        self.assertEqual(chats, ["222", "333", "-100"])
        note = self.bot.sent[2][1]
        self.assertIn("Priya: you asked for this command, so your tap here is Not counted.", note)
        self.assertIn("2 approval(s) are needed from other people: Dev, Sam.", note)
        plugin._on_vote(req.request_id, "222", "deny")
        worker.join(5)

    def test_requester_tap_is_not_counted_shown_in_every_copy_and_ledgered(self):
        req = request()
        worker, out = self.start(req)
        self.assertEqual(plugin._on_vote(req.request_id, "111", "once"), "ignored:requester")
        self.assertTrue(all("Not counted: Priya (requester)" in e[2] for e in self.bot.edits))
        self.assertTrue(all("0 of 2 approved" in e[2] for e in self.bot.edits))
        plugin._on_vote(req.request_id, "222", "once")
        plugin._on_vote(req.request_id, "333", "once")
        worker.join(5)
        self.assertEqual(out[0].choice, "once")
        votes = [e for e in plugin._get_ledger().entries() if e["event"] == "vote"]
        self.assertEqual([(v["voter"], v["result"]) for v in votes],
                         [("111", "ignored:requester"), ("222", "counted"), ("333", "approved")])

    def test_note_goes_to_the_requesters_dm_when_the_turn_has_no_chat_id(self):
        req = request()
        worker, _ = self.start(req, chat_id="")
        self.assertEqual(self.bot.sent[2][0], "111")
        plugin._on_vote(req.request_id, "222", "deny")
        worker.join(5)

    def test_a_failed_note_is_ledgered_and_the_quorum_is_unaffected(self):
        self.bot.fail_chat = "-100"
        req = request()
        worker, out = self.start(req, sends=2)
        plugin._on_vote(req.request_id, "222", "once")
        plugin._on_vote(req.request_id, "333", "once")
        worker.join(5)
        self.assertEqual(out[0].choice, "once")
        failed = [e for e in plugin._get_ledger().entries() if e["event"] == "delivery_failed"]
        self.assertEqual([(f["approver"], "not a member" in f["why"]) for f in failed], [("requester note", True)])

    def test_a_local_requester_gets_no_note(self):
        plugin._policy = lambda: plugin.quorum.parse_policy({"approvers": [
            {"name": "Dev", "telegram_id": "222"}, {"name": "Sam", "telegram_id": "333"}]})
        req = request("ls")
        worker, _ = self.start(req, platform="local", actor_id="uid:501", chat_id="", sends=2)
        time.sleep(0.1)
        self.assertEqual([s[0] for s in self.bot.sent], ["222", "333"])
        plugin._on_vote(req.request_id, "222", "once")
        plugin._on_vote(req.request_id, "333", "once")
        worker.join(5)

    def test_an_impossible_ballot_tells_the_requester_why(self):
        plugin._policy = lambda: plugin.quorum.parse_policy({"approvers": [
            {"name": "Priya", "telegram_id": "111"}, {"name": "Dev", "telegram_id": "222"}], "critical_patterns": [r"rm\s+-rf"]})
        req = request()
        tokens = set_session_vars(platform="telegram", actor_id="111", actor_name="Priya", chat_id="-100")
        try:
            plugin._on_pre_approval_request(request_id=req.request_id)
        finally:
            clear_session_vars(tokens)
        self.assertEqual(plugin.present(req).choice, "deny")
        self.assertEqual(self.bot.sent, [], "no ballot goes to anyone")
        self.assertEqual(len(self.bot.notes), 1)
        chat, text = self.bot.notes[0]
        self.assertEqual(chat, "-100")
        self.assertIn("needs 2 approval(s) from people other than you, and only 1 on the roster qualify", text)

    def test_telling_the_requester_never_raises(self):
        class Down(FakeBot):
            def notify(self, chat_id, text):
                raise TelegramError("sendMessage failed: HTTP 403")
        self.bot = Down()
        with self.assertLogs(plugin.logger, level="INFO") as logs:
            plugin._tell_requester("-100", "x")
        self.assertTrue(any("could not tell the requester" in line for line in logs.output))
        plugin._tell_requester("", "x")  # no chat to tell: nothing happens


class StateFileTests(Base):
    def test_open_ballot_is_published_with_votes_and_refused_taps(self):
        req = request()
        worker, _ = self.start(req)
        plugin._on_vote(req.request_id, "222", "once")
        plugin._on_vote(req.request_id, "111", "once")
        ballot = self.state()["ballots"][0]
        self.assertEqual({a["name"]: a["state"] for a in ballot["approvers"]}, {"Priya": "requester", "Dev": "yes", "Sam": "waiting"})
        self.assertEqual((ballot["tier"], ballot["required"], ballot["command"], ballot["pattern_key"]),
                         ("critical", 2, "rm -rf /srv/builds/staging", "recursive delete"))
        self.assertEqual(ballot["requester"]["name"], "Priya")
        self.assertEqual([(n["name"], n["why"]) for n in ballot["not_counted"]], [("Priya", "requester")])
        self.assertGreater(ballot["opened_at"], 0)
        plugin._on_vote(req.request_id, "333", "once")
        worker.join(5)

    def test_closed_ballot_moves_to_recent_with_outcome_and_ledger_hash(self):
        req = request()
        worker, _ = self.start(req)
        plugin._on_vote(req.request_id, "222", "once")
        plugin._on_vote(req.request_id, "333", "once")
        worker.join(5)
        state = self.state()
        self.assertEqual(state["ballots"], [])
        recent = state["recent"][-1]
        decided = [e for e in plugin._get_ledger().entries() if e["event"] == "decided"][-1]
        self.assertEqual((recent["outcome"], recent["yes"], recent["ledger"]), ("once", ["Dev", "Sam"], decided["hash"]))

    def test_recent_keeps_only_the_last_few_and_survives_a_reload(self):
        for i in range(plugin.RECENT_KEPT + 3):
            plugin._recent.append({"request_id": str(i)})
        del plugin._recent[:-plugin.RECENT_KEPT]
        plugin._publish()
        plugin._recent.clear()
        plugin._ctx = SimpleNamespace(get_config=lambda k: None)
        saved = (plugin._armed_view, plugin._current_view, plugin._armed_file)
        plugin._current_view = lambda: (_ for _ in ()).throw(RuntimeError("no config here"))
        plugin._armed_file = lambda: self.dir / "armed.json"
        try:
            plugin._load_armed()
        finally:
            plugin._armed_view, plugin._current_view, plugin._armed_file = saved
        self.assertEqual([r["request_id"] for r in plugin._recent], [str(i) for i in range(3, 11)])

    def test_a_tripwire_is_published_for_the_pane(self):
        plugin._tripped = ["command_allowlist"]
        try:
            plugin._publish()
            self.assertEqual(self.state()["tripped"], ["command_allowlist"])
        finally:
            plugin._tripped = []

    def test_concurrent_publishes_never_collide_on_the_temp_file(self):
        """The poller thread and the ballot's own thread publish at once; each used to rename the other's temp file away."""
        with self.assertNoLogs(plugin.logger, level="WARNING"):
            threads = [threading.Thread(target=lambda: [plugin._publish() for _ in range(80)]) for _ in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(10)
        self.assertEqual(self.state()["ballots"], [])

    def test_an_unwritable_state_file_is_logged_and_never_blocks_a_decision(self):
        plugin._state_file = lambda: self.dir / "missing" / "state.json"
        with self.assertLogs(plugin.logger, level="WARNING") as logs:
            plugin._publish()
        self.assertTrue(any("could not write the pane state" in line for line in logs.output))


class ClientTests(unittest.TestCase):
    def test_edit_ballot_sends_the_buttons_again(self):
        calls = []
        client = BotClient("123:test")
        client.call = lambda method, payload, timeout=15: calls.append((method, payload)) or {}
        client.edit_ballot("222", 5, "text", "rid")
        method, payload = calls[0]
        self.assertEqual(method, "editMessageText")
        self.assertEqual([b["callback_data"] for b in payload["reply_markup"]["inline_keyboard"][0]], ["sk|rid|once", "sk|rid|deny"])

    def test_edit_ballot_logs_a_refused_edit_instead_of_raising(self):
        client = BotClient("123:test")

        def refuse(*a, **k):
            raise TelegramError("editMessageText failed: HTTP 400 message is not modified")
        client.call = refuse
        with self.assertLogs("second_key_live.telegram", level="INFO"):
            client.edit_ballot("222", 5, "text", "rid")

    def tap(self, result):
        answers = []
        client = SimpleNamespace(answer=lambda cid, text, alert=False: answers.append((text, alert)))
        poller = Poller(client, lambda rid, voter, choice: result)
        poller.handle({"callback_query": {"id": "c", "from": {"id": 1}, "data": "sk|rid|once"}})
        return answers[0]

    def test_a_requester_tap_answers_not_counted_as_an_alert(self):
        text, alert = self.tap("ignored:requester")
        self.assertTrue(text.startswith("Not counted: you asked for this command"))
        self.assertTrue(alert)

    def test_other_refused_taps_alert_and_counted_taps_do_not(self):
        self.assertEqual(self.tap("ignored:not-eligible"), ("Not counted: you cannot vote on this request.", True))
        self.assertEqual(self.tap("counted"), ("Vote counted. Waiting for another approver.", False))


if __name__ == "__main__":
    unittest.main()
