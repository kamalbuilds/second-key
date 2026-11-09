import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("second_key.ledger", ROOT / "second-key" / "ledger.py")
ledger_module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ledger_module
spec.loader.exec_module(ledger_module)


class LedgerTests(unittest.TestCase):
    def test_hash_chain_detects_edit_and_deletion_at_first_break(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = ledger_module.Ledger(path)
            for i in range(3):
                ledger.append("test", index=i)
            self.assertEqual(ledger.verify(), (True, 0))

            lines = path.read_text().splitlines()
            lines[1] = lines[1].replace('"index": 1', '"index": 9')
            path.write_text("\n".join(lines) + "\n")
            self.assertEqual(ledger.verify(), (False, 2))

            path.write_text("\n".join(lines[1:]) + "\n")
            self.assertEqual(ledger.verify(), (False, 1))


if __name__ == "__main__":
    unittest.main()
