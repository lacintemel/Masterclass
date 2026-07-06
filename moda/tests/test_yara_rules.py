from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class YaraRuleTests(unittest.TestCase):
    def test_official_rules_compile_when_yara_is_available(self) -> None:
        try:
            import yara
        except ImportError:
            self.skipTest("yara-python is not installed")

        rules_dir = Path(__file__).resolve().parents[1] / "rules" / "official"
        filepaths = {path.stem: str(path) for path in rules_dir.glob("*.yar")}

        compiled = yara.compile(filepaths=filepaths)

        self.assertIsNotNone(compiled)


if __name__ == "__main__":
    unittest.main()
