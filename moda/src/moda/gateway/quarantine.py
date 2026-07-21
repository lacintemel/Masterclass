"""Filesystem-backed quarantine with opaque identifiers and atomic writes."""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import MessageResult

_QUARANTINE_ID = re.compile(r"^[0-9a-f]{32}$")


class QuarantineStore:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def save(
        self,
        raw_message: bytes,
        *,
        mail_from: str,
        recipients: list[str],
        result: MessageResult,
    ) -> str:
        quarantine_id = uuid.uuid4().hex
        created_at = datetime.now(timezone.utc).isoformat()
        record = {
            "quarantine_id": quarantine_id,
            "created_at": created_at,
            "mail_from": mail_from,
            "recipients": list(recipients),
            "subject": result.subject,
            "message_verdict": result.verdict.value,
            "risk_score": result.max_score,
            "attachments": [item.to_dict() for item in result.attachments],
        }
        eml_path = self._path(quarantine_id, ".eml")
        json_path = self._path(quarantine_id, ".json")
        temp_eml = self._path(quarantine_id, ".eml.tmp")
        temp_json = self._path(quarantine_id, ".json.tmp")
        try:
            temp_eml.write_bytes(raw_message)
            temp_json.write_text(
                json.dumps(record, indent=2, ensure_ascii=False, sort_keys=True),
                encoding="utf-8",
            )
            temp_eml.chmod(0o600)
            temp_json.chmod(0o600)
            os.replace(temp_eml, eml_path)
            os.replace(temp_json, json_path)
        except Exception:
            temp_eml.unlink(missing_ok=True)
            temp_json.unlink(missing_ok=True)
            eml_path.unlink(missing_ok=True)
            json_path.unlink(missing_ok=True)
            raise
        return quarantine_id

    def list_records(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for path in self.root.glob("*.json"):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    records.append(payload)
            except (OSError, json.JSONDecodeError):
                continue
        return sorted(records, key=lambda item: str(item.get("created_at", "")), reverse=True)

    def get(self, quarantine_id: str) -> dict[str, Any] | None:
        path = self._validated_path(quarantine_id, ".json")
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def eml_path(self, quarantine_id: str) -> Path | None:
        path = self._validated_path(quarantine_id, ".eml")
        return path if path.is_file() else None

    def delete(self, quarantine_id: str) -> bool:
        eml_path = self._validated_path(quarantine_id, ".eml")
        json_path = self._validated_path(quarantine_id, ".json")
        existed = eml_path.exists() or json_path.exists()
        eml_path.unlink(missing_ok=True)
        json_path.unlink(missing_ok=True)
        return existed

    def _validated_path(self, quarantine_id: str, suffix: str) -> Path:
        if not _QUARANTINE_ID.fullmatch(quarantine_id):
            raise ValueError("Invalid quarantine identifier")
        return self._path(quarantine_id, suffix)

    def _path(self, quarantine_id: str, suffix: str) -> Path:
        return self.root / f"{quarantine_id}{suffix}"
