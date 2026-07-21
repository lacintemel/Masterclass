#!/usr/bin/env python3
"""Send harmless messages through the local MODA SMTP gateway."""

from __future__ import annotations

import argparse
import smtplib
from email.message import EmailMessage


def build_message(kind: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["To"] = "recipient@example.test"
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["safe", "suspicious", "malicious"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=2525, type=int)
    args = parser.parse_args()

    message = build_message(args.kind)
    try:
        with smtplib.SMTP(args.host, args.port, timeout=10) as client:
            client.send_message(message)
    except smtplib.SMTPDataError as exc:
        print(f"SMTP {exc.smtp_code}: {exc.smtp_error.decode(errors='replace')}")
        return 0 if args.kind == "malicious" and exc.smtp_code == 550 else 1
    print("SMTP 250: message accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
