from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from moda.cli import discover_input_files, run_batch_command, run_doctor_command


def build_docx(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        archive.writestr(
            "word/document.xml",
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
        )


class BatchCLITests(unittest.TestCase):
    def test_discover_input_files_filters_supported_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            build_docx(root / "one.docx")
            (root / "notes.txt").write_text("ignore", encoding="utf-8")
            nested = root / "nested"
            nested.mkdir()
            (nested / "two.pdf").write_bytes(b"%PDF-1.4\n%%EOF")

            shallow = discover_input_files(root, recursive=False)
            recursive = discover_input_files(root, recursive=True)

        self.assertEqual([path.name for path in shallow], ["one.docx"])
        self.assertEqual([path.name for path in recursive], ["two.pdf", "one.docx"])

    def test_run_batch_command_writes_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            build_docx(root / "one.docx")
            (root / "notes.txt").write_text("ignore", encoding="utf-8")
            output = root / "results.jsonl"

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                run_batch_command([str(root), "-o", str(output), "--no-yara"])

            rows = [
                json.loads(line)
                for line in output.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

        self.assertIn("Batch complete: 1/1 analyzed", stdout.getvalue())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["file_info"]["file_name"], "one.docx")
        self.assertEqual(rows[0]["file_info"]["file_type"], "ooxml_docx")

    def test_doctor_command_reports_runtime_checks(self) -> None:
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            run_doctor_command([])

        output = stdout.getvalue()
        self.assertIn("Python >= 3.10", output)
        self.assertIn("Config directory", output)
        self.assertIn("Rules directory", output)
        self.assertIn("UI assets", output)


if __name__ == "__main__":
    unittest.main()
