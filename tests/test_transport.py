import importlib.util
import json
import os
import queue
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from hermes_cli.approval_transport import ApprovalRequest, invoke_approval_transport


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("second_key", ROOT / "second-key" / "__init__.py",
                                              submodule_search_locations=[str(ROOT / "second-key")])
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
from second_key.telegram import BotClient, Poller


class TelegramHandler(BaseHTTPRequestHandler):
    updates = queue.Queue()
    sent = threading.Event()
    next_update = 1
    methods = []

    def do_POST(self):
        method = self.path.rsplit("/", 1)[-1]
        type(self).methods.append((method, self.path))
        size = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(size) or b"{}")
        if method == "sendMessage":
            type(self).sent.set()
            result = {"message_id": 10}
        elif method == "getUpdates":
            try:
                result = [type(self).updates.get(timeout=0.05)]
            except queue.Empty:
                result = []
        else:
            result = True
        body = json.dumps({"ok": True, "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), TelegramHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        TelegramHandler.sent.clear()
        TelegramHandler.methods.clear()
        while not TelegramHandler.updates.empty():
            TelegramHandler.updates.get_nowait()
        self.temp = tempfile.TemporaryDirectory()
        self.client = BotClient("123:test", base_url=self.base_url)
        self.poller = Poller(self.client, plugin._on_vote)
        self.poller.ensure_running()
        self.originals = (plugin._policy, plugin._bot, plugin._get_ledger)
        self.policy = lambda: plugin.quorum.parse_policy({
            "approvers": [{"name": "requester", "telegram_id": "111"},
                          {"name": "approver", "telegram_id": "222"},
                          {"name": "second approver", "telegram_id": "333"}],
            "required": 1, "critical_required": 2, "critical_patterns": [r"rm\s+-rf"],
            "unknown_requester_required": 2,
        })
        plugin._policy = self.policy
        plugin._bot = lambda: (self.client, self.poller)
        plugin._get_ledger = lambda: plugin.Ledger(Path(self.temp.name) / "ledger.jsonl")
        plugin._ledger = None

    def tearDown(self):
        self.poller.stop()
        plugin._policy, plugin._bot, plugin._get_ledger = self.originals
        plugin._bindings.clear()
        plugin._ballots.clear()
        plugin._ledger = None
        self.temp.cleanup()

    def decide(self, voter=None, choice="once", command="echo ok"):
        request = ApprovalRequest.create(command=command, description="test request", pattern_key="shell",
                                        pattern_keys=("shell",), session_key="telegram:111", surface="gateway",
                                        allow_session=False, allow_permanent=False, timeout_seconds=3)
        with patch.dict(os.environ, {"HERMES_SESSION_PLATFORM": "telegram", "HERMES_SESSION_USER_ID": "111"}):
            from gateway.session_context import reset_session_vars
            reset_session_vars()
            plugin._on_pre_approval_request(request_id=request.request_id)
        self.assertEqual(plugin._bindings[request.request_id][0].key, "telegram:111")
        result = []
        worker = threading.Thread(target=lambda: result.append(
            invoke_approval_transport(plugin.present, request, timeout_seconds=10)))
        worker.start()
        if voter is not None:
            self.assertTrue(TelegramHandler.sent.wait(2), f"approval message was not sent; methods={TelegramHandler.methods}")
            TelegramHandler.updates.put({"update_id": TelegramHandler.next_update,
                                         "callback_query": {"id": f"cb-{TelegramHandler.next_update}",
                                                            "from": {"id": voter},
                                                            "data": f"sk|{request.request_id}|{choice}"}})
            TelegramHandler.next_update += 1
        worker.join(10)
        self.assertFalse(worker.is_alive(), "transport did not finish within its deadline")
        return result[0].choice

    def test_too_few_eligible_approvers_denies_without_sending(self):
        plugin._policy = lambda: plugin.quorum.parse_policy(
            {"approvers": [{"name": "requester", "telegram_id": "111"}, {"name": "approver", "telegram_id": "222"}],
             "required": 1, "critical_required": 2, "critical_patterns": [r"rm\s+-rf"]})
        self.assertEqual(self.decide(command="rm -rf /data"), "deny")
        self.assertNotIn("sendMessage", [m for m, _ in TelegramHandler.methods])

    def test_two_other_approvers_meet_critical_quorum(self):
        request_choice = self.decide_two("222", "333", command="rm -rf /data")
        self.assertEqual(request_choice, "once")

    def decide_two(self, first, second, command):
        request = ApprovalRequest.create(command=command, description="test request", pattern_key="shell",
                                        pattern_keys=("shell",), session_key="telegram:111", surface="gateway",
                                        allow_session=False, allow_permanent=False, timeout_seconds=5)
        with patch.dict(os.environ, {"HERMES_SESSION_PLATFORM": "telegram", "HERMES_SESSION_USER_ID": "111"}):
            from gateway.session_context import reset_session_vars
            reset_session_vars()
            plugin._on_pre_approval_request(request_id=request.request_id)
        result = []
        worker = threading.Thread(target=lambda: result.append(
            invoke_approval_transport(plugin.present, request, timeout_seconds=10)))
        worker.start()
        self.assertTrue(TelegramHandler.sent.wait(2))
        for voter in (first, second):
            TelegramHandler.updates.put({"update_id": TelegramHandler.next_update,
                                         "callback_query": {"id": f"cb-{TelegramHandler.next_update}",
                                                            "from": {"id": voter},
                                                            "data": f"sk|{request.request_id}|once"}})
            TelegramHandler.next_update += 1
        worker.join(10)
        return result[0].choice

    def test_other_approver_can_approve_once(self):
        self.assertEqual(self.decide("222"), "once")

    def test_requester_vote_times_out_to_deny(self):
        self.assertEqual(self.decide("111"), "deny")

    def test_approver_can_deny(self):
        self.assertEqual(self.decide("222", "deny"), "deny")

    def test_critical_command_needs_two_and_denies_after_one(self):
        self.assertEqual(self.decide("222", command="rm -rf /data"), "deny")


if __name__ == "__main__":
    unittest.main()
