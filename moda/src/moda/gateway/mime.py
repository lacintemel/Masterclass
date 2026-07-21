"""Bounded MIME parsing and Office attachment extraction."""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path

from moda.core.file_support import SUPPORTED_OFFICE_EXTENSIONS

from .config import GatewayConfig
from .errors import MessageLimitError, MessageParseError

OFFICE_MIME_TYPES = frozenset(
    {
        "application/msword",
        "application/rtf",
        "text/rtf",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/vnd.ms-word.document.macroenabled.12",
        "application/vnd.ms-word.template.macroenabled.12",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
        "application/vnd.ms-excel.sheet.binary.macroenabled.12",
        "application/vnd.ms-excel.sheet.macroenabled.12",
        "application/vnd.ms-excel.template.macroenabled.12",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
        "application/vnd.ms-powerpoint.presentation.macroenabled.12",
        "application/vnd.ms-powerpoint.slideshow.macroenabled.12",
        "application/vnd.ms-powerpoint.template.macroenabled.12",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
        "application/vnd.openxmlformats-officedocument.presentationml.template",
    }
)

_MIME_DEFAULT_NAMES = {
    "application/msword": "attachment.doc",
    "application/rtf": "attachment.rtf",
    "text/rtf": "attachment.rtf",
    "application/vnd.ms-excel": "attachment.xls",
    "application/vnd.ms-powerpoint": "attachment.ppt",
}


@dataclass(frozen=True, slots=True)
class ParsedAttachment:
    filename: str
    content_type: str
    content: bytes
    is_office: bool

    @property
    def size(self) -> int:
        return len(self.content)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True, slots=True)
class ParsedMessage:
    subject: str
    attachments: tuple[ParsedAttachment, ...]


def parse_message(raw_message: bytes, config: GatewayConfig) -> ParsedMessage:
    if len(raw_message) > config.max_message_bytes:
        raise MessageLimitError("Message exceeds the configured maximum size")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_message)
    except Exception as exc:
        raise MessageParseError("MIME parser rejected the message") from exc
    if message.defects:
        defect_names = ", ".join(type(defect).__name__ for defect in message.defects[:3])
        raise MessageParseError(f"Malformed MIME message: {defect_names}")

    attachments: list[ParsedAttachment] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if part.get_content_disposition() != "attachment" and not filename:
            continue
        if len(attachments) >= config.max_attachments:
            raise MessageLimitError("Message contains too many attachments")
        if part.defects:
            raise MessageParseError("Attachment contains malformed MIME encoding")
        content = _decode_attachment(part)
        if len(content) > config.max_attachment_bytes:
            raise MessageLimitError("Attachment exceeds the configured maximum size")
        content_type = part.get_content_type().lower()
        safe_name = _display_filename(filename, content_type, len(attachments) + 1)
        extension_match = Path(safe_name).suffix.lower() in SUPPORTED_OFFICE_EXTENSIONS
        attachments.append(
            ParsedAttachment(
                filename=safe_name,
                content_type=content_type,
                content=content,
                is_office=extension_match or content_type in OFFICE_MIME_TYPES,
            )
        )
    subject = str(message.get("subject", ""))[:500]
    return ParsedMessage(subject=subject, attachments=tuple(attachments))


def _decode_attachment(part: Message) -> bytes:
    transfer_encoding = str(part.get("Content-Transfer-Encoding", "")).lower()
    payload = part.get_payload()
    if transfer_encoding == "base64" and isinstance(payload, str):
        try:
            compact = "".join(payload.split()).encode("ascii")
            return base64.b64decode(compact, validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
            raise MessageParseError("Attachment has invalid base64 content") from exc
    try:
        decoded = part.get_payload(decode=True)
    except Exception as exc:
        raise MessageParseError("Attachment payload could not be decoded") from exc
    if decoded is None:
        if isinstance(payload, str):
            return payload.encode(part.get_content_charset() or "utf-8", errors="replace")
        raise MessageParseError("Attachment payload is not byte content")
    if isinstance(decoded, bytes):
        return decoded
    raise MessageParseError("Attachment payload is not byte content")


def _display_filename(filename: str | None, content_type: str, index: int) -> str:
    if filename:
        normalized = Path(filename.replace("\\", "/")).name.strip()
        if normalized not in {"", ".", ".."}:
            return normalized[:255]
    return _MIME_DEFAULT_NAMES.get(content_type, f"attachment-{index}.bin")
