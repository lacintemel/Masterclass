# MODA - Malicious Office Document Analyzer

MODA is a static analysis tool for Microsoft Office documents, RTF files, and PDFs.
It is built for triage workflows where analysts need hashes, metadata, suspicious
structure indicators, IOCs, risk scoring, and portable reports without executing or
rendering the submitted document.

## What MODA Analyzes

- Office binary documents: `.doc`, `.xls`, `.ppt`
- Office binary templates/add-ins where they use the same OLE structure:
  `.dot`, `.xla`, `.xlt`, `.pps`, `.pot`, `.ppa`
- Office Open XML documents: `.docx`, `.docm`, `.dotx`, `.dotm`, `.xlsx`,
  `.xlsm`, `.xlsb`, `.xltx`, `.xltm`, `.xlam`, `.pptx`, `.pptm`, `.ppsx`,
  `.ppsm`, `.potx`, `.potm`, `.ppam`
- Rich Text Format: `.rtf`
- PDFs: `.pdf`

Unsupported file types are reported as inconclusive instead of clean. MODA is
focused on document triage, not general PE/ELF malware classification.

## Safety Model

MODA never opens documents in Office, never executes macros, and never renders file
content. Analysis is performed through static parsing, byte scanning, string
extraction, relationship inspection, rule matching, and configurable scoring.

## Features

- File type detection with magic-byte and OOXML package validation
- MD5, SHA1, and SHA256 hash generation
- Metadata extraction for OOXML, OLE, and PDF where supported
- OOXML structure inspection, package profiling, macro project detection, DDE
  fields, active content markers, suspicious command text, and embedded object
  discovery
- Excel-specific checks for external links, data connections, query tables,
  suspicious formulas, and veryHidden sheets
- OLE stream analysis for macro storage, ObjectPool, embedded packages, ActiveX,
  encrypted Office packages, Equation/DDE hints, high-entropy VBA streams, and
  large directory trees
- PDF action and JavaScript keyword detection
- RTF object, DDE, and exploit-marker detection
- Static macro heuristics for auto-run triggers, shell execution, downloaders,
  obfuscation, and native API abuse
- Embedded payload classification for scripts, PE files, OLE objects, ActiveX,
  nested PDFs, and nested archives
- External relationship and remote template detection
- IOC extraction for URLs, IPs, hashes, paths, commands, and executables
- Optional YARA scanning
- Risk scoring
- Console, JSON, HTML, and PDF reports
- Local browser UI
- Batch directory analysis with JSONL output

## Requirements

Use Python 3.10 or newer. Python 3.12 is recommended.

Some dependencies are optional at runtime. MODA degrades gracefully when packages
such as `yara-python`, `python-magic`, `olefile`, `pypdf`, or `rich` are missing,
but installing the full requirements enables deeper analysis and nicer console
output.

## Install

From this repository:

```bash
cd /Users/lacintemel/Desktop/projects/Masterclass/moda
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

For development:

```bash
python -m pip install -r requirements-dev.txt
```

If you do not install the package, run commands with `PYTHONPATH=src`.

## CLI Usage

Analyze one file and print a console report:

```bash
PYTHONPATH=src python3.12 -m moda sample.docm --no-yara
```

Write JSON:

```bash
PYTHONPATH=src python3.12 -m moda sample.docm --format json --output report.json --no-yara
```

Write HTML:

```bash
PYTHONPATH=src python3.12 -m moda sample.pdf --format html --output report.html --no-yara
```

Write PDF:

```bash
PYTHONPATH=src python3.12 -m moda sample.rtf --format pdf --output report.pdf --no-yara
```

Run batch analysis:

```bash
PYTHONPATH=src python3.12 -m moda batch /path/to/documents --recursive --output results.jsonl --no-yara
```

Check runtime readiness:

```bash
PYTHONPATH=src python3.12 -m moda doctor
```

Start the local web UI:

```bash
PYTHONPATH=src python3.12 -m moda ui --no-yara
```

Then open:

```text
http://127.0.0.1:8765
```

## YARA

MODA recursively loads YARA files from:

- `rules/official/` for built-in MODA rules
- `rules/custom/` for local analyst rules
- `rules/external/` for third-party rulesets kept outside the core rules
- `rules/community/` for curated community rules you choose to keep in-repo

Use `--no-yara` to skip YARA scanning when `yara-python` is not installed or
when fast triage is preferred.

Third-party source manifest:

```text
rules/external_sources.yml
```

The manifest includes well-known public sources such as Neo23x0/signature-base,
YARA-Forge, Elastic Security protections artifacts, Yara-Rules/rules, and
InQuest awesome-yara. Review each source license before vendoring or
redistributing rules. Some public rules require external variables or optional
YARA modules; MODA skips rule files that fail compilation and records those
compile errors in the analysis result instead of disabling all YARA scanning.

## Test

```bash
python3.12 -m unittest discover -s tests
```

The UI integration test binds a local ephemeral port.

## Current Status

MODA is a working static-analysis MVP with CLI, browser UI, batch mode, multiple
report formats, and broad static heuristics. It is not a replacement for a full
malware sandbox. Treat output as triage evidence and review suspicious findings
manually in a controlled workflow.
