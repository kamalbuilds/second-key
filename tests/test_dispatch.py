import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1] / "second-key"
spec = importlib.util.spec_from_file_location("second_key_dispatch", ROOT / "__init__.py",
                                              submodule_search_locations=[str(ROOT)])
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)


def event(text, platform, user_id):
    return SimpleNamespace(text=text, source=SimpleNamespace(platform=SimpleNamespace(value=platform), user_id=user_id))


class YoloGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.originals = (plugin._policy, plugin._get_ledger)
        plugin._policy = lambda: plugin.quorum.parse_policy({"approvers": [
            {"name": "Dev", "telegram_id": "222", "aliases": ["discord:42"]}]})
        plugin._get_ledger = lambda: plugin.Ledger(Path(self.temp.name) / "ledger.jsonl")

    def tearDown(self):
        plugin._policy, plugin._get_ledger = self.originals
        self.temp.cleanup()

    def test_yolo_from_non_roster_is_dropped(self):
        out = plugin._on_pre_gateway_dispatch(event=event("/yolo", "telegram", "999"))
        self.assertEqual(out["action"], "skip")

    def test_yolo_from_roster_member_passes(self):
        self.assertIsNone(plugin._on_pre_gateway_dispatch(event=event("/yolo on", "telegram", "222")))
        self.assertIsNone(plugin._on_pre_gateway_dispatch(event=event("/YOLO", "discord", "42")))

    def test_other_messages_pass(self):
        self.assertIsNone(plugin._on_pre_gateway_dispatch(event=event("run the tests", "telegram", "999")))

    def test_bad_config_drops_yolo(self):
        plugin._policy = lambda: plugin.quorum.parse_policy({"approvers": [{"name": "x"}]})
        self.assertEqual(plugin._on_pre_gateway_dispatch(event=event("/yolo", "telegram", "222"))["action"], "skip")


if __name__ == "__main__":
    unittest.main()
