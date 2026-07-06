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

## Project Tour

MODA follows a simple static-analysis pipeline:

```text
input file
  -> AnalysisContext
  -> analyzers
  -> IOC/YARA enrichment
  -> RiskScorer
  -> AnalysisResult
  -> console/json/html/pdf/UI report
```

The main entry point is `src/moda/core/engine.py`. `AnalyzerEngine` reads the
file once, creates an `AnalysisContext`, runs each analyzer in order, and freezes
the final state into an `AnalysisResult`.

Important modules:

- `src/moda/cli.py` implements the command line, `doctor`, `batch`, and `ui`
  commands.
- `src/moda/core/` contains shared models, enums, exceptions, the base analyzer
  class, context object, and pipeline engine.
- `src/moda/analyzers/` contains static document analyzers:
  - `file_type.py`: magic-byte, MIME, extension, and OOXML package validation.
  - `hash_generator.py`: MD5, SHA1, SHA256 and hash IOCs.
  - `metadata.py`: OOXML/OLE/PDF metadata extraction where supported.
  - `ooxml.py`: DOCX/XLSX/PPTX structure, macro projects, DDE, ActiveX,
    exploit protocols, Excel links/connections/formulas, hidden sheets.
  - `ole.py`: legacy DOC/XLS/PPT stream inspection, VBA storage, ObjectPool,
    packages, ActiveX, encrypted packages, Equation/DDE hints.
  - `macro.py`: static macro string extraction and heuristics for auto-run,
    command execution, downloaders, obfuscation, and native API abuse.
  - `embedded.py`: embedded script, PE, OLE, ActiveX, nested PDF/ZIP detection.
  - `relationship.py`: OOXML external relationships, remote templates, OLE
    links, exploit protocol targets, and remote URL extraction.
  - `pdf.py`: PDF JavaScript, OpenAction, Launch, URI, embedded files, forms,
    object streams, and appended-content hints.
  - `rtf.py`: RTF object, objdata, DDE, Equation exploit markers, and hex blobs.
- `src/moda/intelligence/` contains IOC extraction and YARA scanning.
- `src/moda/scoring/risk_scorer.py` converts findings/YARA matches into a
  0-100 risk score with colored component breakdowns, potential impact, and
  recovery guidance.
- `src/moda/reporting/` renders console, JSON, HTML, and dependency-free PDF
  reports.
- `src/moda/ui/` is a local browser UI served by a small stdlib HTTP server.
- `rules/` contains built-in, custom, external, and community YARA rules.
- `tests/` contains regression tests for analyzers, reporting, UI, CLI, and
  YARA rule compilation/matching.

## Analysis Pipeline Details

Default analyzer order:

1. `FileTypeDetector`
2. `HashGenerator`
3. `MetadataAnalyzer`
4. `OLEAnalyzer`
5. `OOXMLAnalyzer`
6. `RTFAnalyzer`
7. `PDFAnalyzer`
8. `MacroAnalyzer`
9. `EmbeddedObjectAnalyzer`
10. `RelationshipAnalyzer`
11. `IOCExtractor`
12. `YaraScanner`
13. `RiskScorer`

Analyzers communicate through `AnalysisContext`: they add findings, IOCs, YARA
matches, metadata, macro strings, embedded strings, errors, and `extra` details.
Reporters consume only the immutable `AnalysisResult` returned by the engine.

Unsupported file types are not marked clean. MODA reports them as inconclusive
with an `Unsupported File Type` finding because the tool is document-focused and
does not try to replace a PE/ELF sandbox or full malware scanner.

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

## Agent Handoff Notes

If another agent needs to understand or extend this project, give it this
README plus the following checklist:

- Start with `src/moda/core/engine.py` to understand pipeline order.
- Read `src/moda/core/context.py` and `src/moda/core/models.py` to understand
  what analyzers can write and what reporters receive.
- Add new detection logic in the narrowest analyzer that owns that file format
  or behavior.
- Add a focused regression test in `tests/test_static_analyzers.py` or
  `tests/test_yara_rules.py` for every new detection.
- Run `python -m unittest discover -s tests` and `moda doctor` before claiming
  the change is complete.
- Keep third-party YARA rules in `rules/external/` or `rules/community/`;
  review licenses before committing or redistributing them.
- Avoid executing documents, macros, embedded scripts, or payloads. MODA is a
  static triage tool by design.

## Current Status

MODA is a working static-analysis MVP with CLI, browser UI, batch mode, multiple
report formats, and broad static heuristics. It is not a replacement for a full
malware sandbox. Treat output as triage evidence and review suspicious findings
manually in a controlled workflow.
