import importlib.util
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1] / "second-key"
spec = importlib.util.spec_from_file_location("second_key_pane_api", ROOT / "dashboard" / "plugin_api.py")
api = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = api
spec.loader.exec_module(api)

SETTINGS = {"approvers": [{"name": "Priya", "telegram_id": "1"}, {"name": "Dev", "telegram_id": "2"},
                          {"name": "Sam", "telegram_id": "3"}], "required": 1, "critical_required": 3}


class PaneStateTests(unittest.TestCase):
    """The pane's single read: ballots, risk tiers, armed state and the ledger chain."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.data = Path(self.temp.name)
        cfg = {"plugins": {"entries": {"second-key": {"settings": SETTINGS}}}}
        patches = [patch.object(api, "_data_dir", lambda: self.data),
                   patch("hermes_cli.config.load_config_readonly", lambda: cfg)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.temp.cleanup)
        book = api._sibling("ledger").Ledger(self.data / "ledger.jsonl")
        for i in range(3):
            book.append("presented", command=f"rm -r /srv/builds/staging-{i}", required=1, delivered=2)

    def test_tiers_and_roster_come_from_the_config_the_gate_enforces(self):
        out = api.state(14)
        self.assertEqual([p["name"] for p in out["roster"]], ["Priya", "Dev", "Sam"])
        self.assertEqual({t["tier"]: t["required"] for t in out["tiers"]}, {"standard": 1, "critical": 3, "unknown": 2})

    def test_open_ballot_is_listed_and_a_long_dead_one_is_not(self):
        now = time.time()
        (self.data / "state.json").write_text(json.dumps({"ballots": [
            {"request_id": "live", "opened_at": now - 5, "timeout": 60},
            {"request_id": "dead", "opened_at": now - 500, "timeout": 60}]}))
        self.assertEqual([b["request_id"] for b in api.state(14)["ballots"]], ["live"])

    def test_chain_reports_the_first_broken_link(self):
        self.assertEqual((api.state(14)["ledger"]["ok"], api.state(14)["ledger"]["total"]), (True, 3))
        path = self.data / "ledger.jsonl"
        lines = path.read_text().splitlines()
        lines[1] = lines[1].replace("staging-1", "staging-9")
        path.write_text("\n".join(lines) + "\n")
        ledger = api.state(14)["ledger"]
        self.assertFalse(ledger["ok"])
        self.assertEqual(ledger["broken_at"], 2)
        self.assertFalse(ledger["entries"][1]["ok"])

    def test_unarmed_profile_reads_not_armed(self):
        self.assertEqual(api.state(14)["armed"]["state"], "not armed")


if __name__ == "__main__":
    unittest.main()
