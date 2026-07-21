import importlib.util
from pathlib import Path
from types import ModuleType

import pytest


def _load_sender_module() -> ModuleType:
    script_path = Path(__file__).parents[1] / "send_test_mail.py"
    spec = importlib.util.spec_from_file_location("send_test_mail", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_file_message = _load_sender_module().build_file_message


def test_build_file_message_attaches_selected_file(tmp_path: Path) -> None:
    attachment = tmp_path / "sample.docx"
    attachment.write_bytes(b"inert-test-content")

    message = build_file_message(attachment)
    parts = list(message.iter_attachments())

    assert message["To"] == "recipient@example.test"
    assert message["Subject"] == "MODA file analysis: sample.docx"
    assert len(parts) == 1
    assert parts[0].get_filename() == "sample.docx"
    assert parts[0].get_content_type() == (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    assert parts[0].get_payload(decode=True) == b"inert-test-content"


def test_build_file_message_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a regular file"):
        build_file_message(tmp_path / "missing.docx")
