from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
import urllib.request
import zipfile
from collections import OrderedDict
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from moda.ui.server import MODAUIHandler


def build_docx(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        archive.writestr(
            "docProps/core.xml",
            (
                "<cp:coreProperties "
                'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                'xmlns:dc="http://purl.org/dc/elements/1.1/">'
                "<dc:creator>UI Analyst</dc:creator>"
                "</cp:coreProperties>"
            ),
        )
        archive.writestr(
            "word/document.xml",
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
        )


class MODAUIServerTests(unittest.TestCase):
    def _configure_cache(self, server: ThreadingHTTPServer) -> None:
        server.result_cache = OrderedDict()
        server.cache_lock = threading.Lock()
        server.analysis_semaphore = threading.BoundedSemaphore(2)
        server.max_concurrent_analyses = 2
        server.access_token = ""

    def test_analyze_endpoint_returns_result_json(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), MODAUIHandler)
        server.skip_yara = False
        server.max_size_mb = 100
        server.verbose = False
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                sample = Path(temp_dir) / "ui sample.docx"
                build_docx(sample)
                url = f"http://127.0.0.1:{server.server_port}/api/analyze?yara=0"
                request = urllib.request.Request(
                    url,
                    data=sample.read_bytes(),
                    method="POST",
                    headers={
                        "Content-Type": "application/octet-stream",
                        "X-Filename": "ui%20sample.docx",
                    },
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertEqual(payload["file_info"]["file_name"], "ui sample.docx")
        self.assertEqual(payload["file_info"]["file_type"], "ooxml_docx")
        self.assertEqual(payload["metadata"]["Author"], "UI Analyst")
        self.assertEqual(payload["risk"]["level"], "low")

    def test_ui_returns_legacy_office_and_office_xml_findings(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), MODAUIHandler)
        server.skip_yara = False
        server.max_size_mb = 100
        server.verbose = False
        self._configure_cache(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        ole_payload = (
            b"\xd0\xcf\x11\xe0\x00\x00\x00\x00"
            b"Sub AutoOpen CreateObject WScript.Shell powershell cmd.exe"
        )
        xml_payload = (
            b'<?xml version="1.0"?><?mso-application progid="Excel.Sheet"?>'
            b'<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" '
            b'xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">'
            b'<Worksheet ss:Name="Sheet1"><Table><Row><Cell '
            b'ss:HRef="http://evil.example/payload"><Data ss:Type="String">'
            b"powershell cmd.exe</Data></Cell></Row></Table></Worksheet></Workbook>"
        )
        samples = {
            "sample.xls": (ole_payload, "ole_xls"),
            "sample.pps": (ole_payload, "ole_ppt"),
            "sample.ppt": (ole_payload, "ole_ppt"),
            "sample.xml": (xml_payload, "office_xml"),
        }
        payloads: dict[str, dict] = {}
        try:
            for filename, (content, _) in samples.items():
                request = urllib.request.Request(
                    f"http://127.0.0.1:{server.server_port}/api/analyze?yara=0",
                    data=content,
                    method="POST",
                    headers={"X-Filename": filename},
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    payloads[filename] = json.loads(response.read().decode("utf-8"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        for filename, (_, expected_type) in samples.items():
            with self.subTest(filename=filename):
                payload = payloads[filename]
                self.assertEqual(payload["file_info"]["file_type"], expected_type)
                self.assertGreater(len(payload["findings"]), 0)
                self.assertGreater(payload["risk"]["score"], 0)

    def test_report_endpoint_returns_pdf(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), MODAUIHandler)
        server.skip_yara = False
        server.max_size_mb = 100
        server.verbose = False
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                sample = Path(temp_dir) / "ui report.docx"
                build_docx(sample)
                url = f"http://127.0.0.1:{server.server_port}/api/report?yara=0&lang=tr"
                request = urllib.request.Request(
                    url,
                    data=sample.read_bytes(),
                    method="POST",
                    headers={
                        "Content-Type": "application/octet-stream",
                        "X-Filename": "ui%20report.docx",
                    },
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    content_type = response.headers.get("Content-Type")
                    body = response.read()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertEqual(content_type, "application/pdf")
        self.assertTrue(body.startswith(b"%PDF-1.4"))
        self.assertIn(b"%%EOF", body)
        self.assertIn("YÖNETİCİ ÖZETİ".encode("cp1254"), body)

    def test_report_endpoint_uses_cached_analysis_without_reupload(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), MODAUIHandler)
        server.skip_yara = False
        server.max_size_mb = 100
        server.verbose = False
        self._configure_cache(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                sample = Path(temp_dir) / "cached.docx"
                build_docx(sample)
                analyze_request = urllib.request.Request(
                    f"http://127.0.0.1:{server.server_port}/api/analyze?yara=0",
                    data=sample.read_bytes(),
                    method="POST",
                    headers={"X-Filename": "cached.docx"},
                )
                with urllib.request.urlopen(analyze_request, timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))

                analysis_id = payload["extra"]["analysis_id"]
                report_request = urllib.request.Request(
                    f"http://127.0.0.1:{server.server_port}/api/report?analysis_id={analysis_id}&lang=en",
                    data=b"",
                    method="POST",
                )
                with urllib.request.urlopen(report_request, timeout=5) as response:
                    body = response.read()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertTrue(body.startswith(b"%PDF-1.4"))


if __name__ == "__main__":
    unittest.main()
