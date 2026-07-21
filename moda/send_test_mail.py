#!/usr/bin/env python3
"""Send simulations or a selected attachment through the MODA SMTP gateway."""

from __future__ import annotations

import argparse
import mimetypes
import smtplib
from email.message import EmailMessage
from pathlib import Path

DEFAULT_FROM = "sender@example.test"
DEFAULT_TO = "recipient@example.test"


def build_message(kind: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = DEFAULT_FROM
    message["To"] = DEFAULT_TO
    message["Subject"] = f"MODA gateway {kind} simulation"
    message.set_content("This message contains only a harmless gateway test attachment.")
    filename = {
        "safe": "quarterly-report.docx",
        "suspicious": "suspicious-quarterly-report.docx",
        "malicious": "quarterly-report.docx",
    }[kind]
    content = b"MDOA_TEST_MALICIOUS" if kind == "malicious" else b"MDOA_TEST_SAFE"
    message.add_attachment(
        content,
        maintype="application",
        subtype="vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename=filename,
    )
    return message


def build_file_message(
    file_path: Path,
    *,
    sender: str = DEFAULT_FROM,
    recipient: str = DEFAULT_TO,
    subject: str | None = None,
) -> EmailMessage:
    """Build a message containing an existing file without opening or executing it."""
    if not file_path.is_file():
        raise ValueError(f"Attachment is not a regular file: {file_path}")

    content_type, _encoding = mimetypes.guess_type(file_path.name)
    maintype, subtype = (content_type or "application/octet-stream").split("/", 1)

    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject or f"MODA file analysis: {file_path.name}"
    message.set_content(
        "This attachment was submitted to the local MODA gateway for analysis."
    )
    message.add_attachment(
        file_path.read_bytes(),
        maintype=maintype,
        subtype=subtype,
        filename=file_path.name,
    )
    return message


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "kind",
        nargs="?",
        choices=["safe", "suspicious", "malicious"],
        help="send an inert built-in simulation",
    )
    parser.add_argument(
        "--file",
        type=Path,
        help="attach this existing file instead of a built-in simulation",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=2525, type=int)
    parser.add_argument("--from-address", default=DEFAULT_FROM)
    parser.add_argument("--to", default=DEFAULT_TO)
    parser.add_argument("--subject")
    args = parser.parse_args()

    if bool(args.kind) == bool(args.file):
        parser.error("choose exactly one: a simulation kind or --file PATH")

    if args.file:
        try:
            message = build_file_message(
                args.file,
                sender=args.from_address,
                recipient=args.to,
                subject=args.subject,
            )
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    else:
        message = build_message(args.kind)
    try:
        with smtplib.SMTP(args.host, args.port, timeout=10) as client:
            client.send_message(message)
    except smtplib.SMTPDataError as exc:
        detail = (
            exc.smtp_error.decode(errors="replace")
            if isinstance(exc.smtp_error, bytes)
            else str(exc.smtp_error)
        )
        print(f"SMTP {exc.smtp_code}: {detail}")
        return 0 if args.kind == "malicious" and exc.smtp_code == 550 else 1
    print("SMTP 250: message accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
