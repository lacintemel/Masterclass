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
- Microsoft Office 2003 XML / SpreadsheetML documents: `.xml` when an Office
  namespace or `mso-application` declaration is present
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
- Structural PDF action/object inspection with bounded raw-byte fallback
- RTF object, DDE, and exploit-marker detection
- Static macro heuristics for auto-run triggers, shell execution, downloaders,
  obfuscation, and native API abuse
- Embedded payload classification for scripts, PE files, OLE objects, ActiveX,
  nested PDFs, and nested archives
- External relationship and remote template detection
- IOC extraction for URLs, domains, public IPs, email addresses, registry keys,
  paths, commands, and executables; file identity hashes are reported separately
- Optional YARA scanning
- Risk scoring
- Console, JSON, HTML, and PDF reports
- Local browser UI
- Local SMTP security gateway simulation with Mailpit, quarantine, health checks,
  and a separate administration dashboard
- Batch directory analysis with JSONL output
- Archive decompression, member-count, string-count, IOC-count, and concurrency
  safety budgets
- Per-analyzer execution status with `complete`, `partial`, and `inconclusive`
  analysis-completeness states

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
  - `hash_generator.py`: MD5, SHA1, and SHA256 artifact identity hashes.
  - `metadata.py`: OOXML/OLE/PDF metadata extraction where supported.
  - `ooxml.py`: DOCX/XLSX/PPTX structure, macro projects, DDE, ActiveX,
    exploit protocols, Excel links/connections/formulas, hidden sheets.
  - `office_xml.py`: Office 2003 XML/SpreadsheetML external links, commands,
    DDE, auto-execution markers, metadata, and embedded encoded data.
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
- `src/moda/gateway/` contains the SMTP policy processor, bounded MIME parser,
  direct analyzer adapter, relay, quarantine store, health endpoint, and local
  administration UI.
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
Reporters consume a read-only result snapshot returned by the engine.

Every result also records analyzer execution status. A skipped, unavailable, or
failed capability is visible in JSON, UI, HTML, console, and PDF output. Resource
budget failures and unsupported formats produce an `inconclusive` result rather
than an apparently clean result.

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

Use custom rules and scoring configuration:

```bash
PYTHONPATH=src python3.12 -m moda sample.docm --rules /path/to/rules --config /path/to/scoring.yaml
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

Non-loopback binding is rejected by default. To deliberately expose the UI,
use `--allow-remote` and provide `--token` or `MODA_UI_TOKEN`. Remote deployments
should still be placed behind TLS and a trusted reverse proxy.

### Report chatbot

The web UI includes an optional evidence-grounded assistant. It sends a bounded,
structured version of the cached analysis result—not the uploaded document—to the
configured provider. The context includes risk components, complete finding records
and evidence, IOC context and confidence, YARA metadata, bounded macro excerpts,
analysis errors, metadata, and response recommendations. Report values are marked as
untrusted so document text cannot become model instructions.

For OpenAI:

```bash
export LLM_PROVIDER=openai
export OPENAI_API_KEY="your-key"
export OPENAI_MODEL=gpt-5.6-terra
PYTHONPATH=src python3.12 -m moda ui --no-yara
```

For Gemini:

```bash
export LLM_PROVIDER=gemini
export GEMINI_API_KEY="your-key"
export GEMINI_MODEL=gemini-3.5-flash-lite
PYTHONPATH=src python3.12 -m moda ui --no-yara
```

Alternatively, copy `.env.example` to `.env`, fill in one key, and load it into
the shell before starting the UI:

```bash
set -a
source .env
set +a
```

Keep `.env` out of version control. API keys are read only by the Python backend
and are never returned to browser JavaScript. `LLM_MAX_CONTEXT_CHARS` bounds the
report payload; when a very large report is shortened, the context records the
number of omitted entries. Chat history is limited to the last eight messages.

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
pytest --cov=moda --cov-report=term-missing --cov-fail-under=75
ruff check src tests
mypy src
python -m build
```

The UI integration test binds a local ephemeral port.

## Local SMTP Security Gateway

The repository includes a development-only SMTP gateway simulation. It accepts
mail on `localhost:2525`, scans Office attachments with MODA, and applies this
policy:

```text
test mail client -> gateway :2525 -> MIME/attachment limits -> MODA
                                                   | safe       -> Mailpit :1025
                                                   | suspicious -> quarantine + SMTP 250
                                                   | malicious  -> quarantine + SMTP 550
```

`malicious` has priority over `suspicious`, which has priority over `safe`. A
message without Office attachments is in scope for relay and is considered safe.
Non-Office attachments are recorded but not classified by MODA. The original raw
message and SMTP envelope sender/recipients are preserved during safe relay.

This is a local demonstration and testing gateway. It is not hardened or
supported as a production MTA, Internet-facing MX, data-loss prevention product,
or malware sandbox.

### Start with Docker

Docker and Docker Compose are required. Optional local settings can be copied
from `.env.example`:

```bash
cp .env.example .env
docker compose up --build
```

Compose publishes every service only on the host loopback interface:

- SMTP gateway: `localhost:2525`
- Gateway health: <http://localhost:8080/health>
- Gateway administration UI: <http://localhost:8081>
- Mailpit mailbox UI: <http://localhost:8025>

Inside the Compose network, the gateway relays to `mailpit:1025`. Only messages
with recipients in `ACCEPTED_RECIPIENT_DOMAINS` are accepted, preventing use as
an open relay. The administration UI binds to `0.0.0.0` only inside its container;
the Docker host publication remains `127.0.0.1`.

### Send harmless test messages

Simulation mode is enabled by default. These commands create only inert text
attachments; no malware is generated or used:

```bash
python send_test_mail.py safe
python send_test_mail.py suspicious
python send_test_mail.py malicious
```

To submit an existing attachment to a gateway on another host, pass an absolute
path and the gateway address:

```bash
python send_test_mail.py --file "/absolute/path/to/sample.docx" --host 192.168.228.135
```

Use suspect files only in an isolated lab. The sender reads the attachment as
bytes and does not open it, but the file should not be previewed or executed.

Expected behavior:

| Test | SMTP result | Mailpit | Quarantine |
|---|---|---|---|
| safe | `250 2.0.0` | delivered | no |
| suspicious | `250 2.0.0` | not delivered | `.eml` + `.json` |
| malicious | `550 5.7.1` | not delivered | `.eml` + `.json` |

The malicious simulation uses only the literal marker
`MDOA_TEST_MALICIOUS`. A filename containing `suspicious` produces the middle
verdict. Quarantine records are visible in the administration UI and under the
host `quarantine/` directory.

Run gateway tests inside the container:

```bash
docker compose exec gateway pytest
```

### Run without Docker

Start a local SMTP sink such as Mailpit on port 1025, install the project, and
keep the administration UI on loopback:

```bash
export SIMULATE_ANALYZER=true
export ACCEPTED_RECIPIENT_DOMAINS=example.test
export QUARANTINE_PATH="$PWD/quarantine"
moda-gateway
```

`WEB_UI_HOST` must be `127.0.0.1`, `::1`, or `localhost` outside a container.
The gateway does not depend on either of MODA's browser interfaces to process
SMTP traffic.

### Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `SMTP_LISTEN_HOST` | `127.0.0.1` | SMTP bind address |
| `SMTP_LISTEN_PORT` | `2525` | SMTP gateway port |
| `RELAY_HOST` | `127.0.0.1` | downstream SMTP server |
| `RELAY_PORT` | `1025` | downstream SMTP port |
| `HEALTH_HOST` / `HEALTH_PORT` | `127.0.0.1` / `8080` | health endpoint bind |
| `WEB_UI_HOST` / `WEB_UI_PORT` | `127.0.0.1` / `8081` | admin UI bind |
| `SIMULATE_ANALYZER` | `true` | harmless deterministic verdict mode |
| `ANALYZER_TIMEOUT_SECONDS` | `30` | maximum caller wait for a scan |
| `MAX_MESSAGE_BYTES` | `26214400` | maximum raw SMTP message size |
| `MAX_ATTACHMENT_BYTES` | `20971520` | maximum decoded attachment size |
| `MAX_ATTACHMENTS` | `20` | maximum attachment count |
| `ACCEPTED_RECIPIENT_DOMAINS` | `example.test` | comma-separated exact recipient domains |
| `QUARANTINE_PATH` | `quarantine` | protected `.eml`/`.json` storage |
| `SKIP_YARA` | `false` | disable YARA only when explicitly required |
| `LLM_PROVIDER` | `openai` | optional report chatbot provider (`openai` or `gemini`) |
| `OPENAI_MODEL` | `gpt-5.6-terra` | OpenAI chatbot model |
| `GEMINI_MODEL` | `gemini-3.5-flash-lite` | Gemini chatbot model |
| `LLM_TIMEOUT_SECONDS` | `90` | hosted model request timeout |
| `LLM_MAX_CONTEXT_CHARS` | `60000` | maximum structured report context size |
| `LLM_MAX_OUTPUT_TOKENS` | `1600` | maximum chatbot response tokens |
| `LLM_MAX_RETRIES` | `3` | retries for transient 408/429/5xx and network errors |

`.env.example` also documents `ANALYZER_URL` as a reserved compatibility value.
The current repository already exposes a safe Python API, so the gateway invokes
`AnalyzerEngine` directly and does not add an unnecessary HTTP analyzer service.
The gateway itself requires no credentials. The optional report chatbot requires
one provider API key, which belongs in the ignored `.env` file and is never committed.

### Real analyzer mode and failure policy

Set `SIMULATE_ANALYZER=false` to analyze Office attachments with the in-process
MODA engine. Risk levels map as follows:

- low + complete analysis -> `safe`
- medium or partial/inconclusive analysis -> `suspicious`
- high or critical -> `malicious`

Analyzer exceptions, timeouts, invalid/unrecognized results, malformed MIME, and
invalid base64 never become `safe`. Transient scan failures return
`451 4.7.0`; downstream relay failures return `451 4.4.1`. Message, attachment,
attachment-count, archive expansion, nested payload, string, and IOC budgets limit
resource use. Logs are JSON event records and never contain attachment bytes or
the full message body.

The health response distinguishes SMTP, analyzer, and relay state:

```json
{"status":"healthy","smtp":true,"analyzer":true,"relay":true}
```

If Mailpit is unavailable, status becomes `degraded` and `relay` is `false`.

### Quarantine and administration

Each suspicious or malicious message creates an opaque UUID pair:

```text
quarantine/<id>.eml
quarantine/<id>.json
```

The JSON record contains envelope metadata, subject, message verdict, attachment
names, MIME types, sizes, SHA-256 hashes, scores, analyzer completeness, and
reasons. Original attachment filenames are never used as filesystem paths.
Writes are atomic and files are created with owner-only permissions where the
platform supports them.

The local administration UI provides dashboard counters, recent events,
quarantine listing/detail, controlled raw `.eml` download, and CSRF-protected
deletion. It deliberately offers no Office attachment preview.

### Common gateway problems

- `451 4.4.1`: Mailpit or the configured relay is unavailable. Check
  `docker compose ps` and the health endpoint.
- `451 4.7.0`: parsing or analysis did not complete safely. Retry after checking
  the structured `analysis_failed` event.
- `550 5.7.1 Relaying denied`: the recipient domain is not in
  `ACCEPTED_RECIPIENT_DOMAINS`.
- `552 5.3.4`: the raw message, decoded attachment, or attachment count exceeded
  a configured safety limit.
- Admin UI refuses to start outside Docker: use a loopback `WEB_UI_HOST`.

### Path toward a real MX deployment

For a future production design, keep MODA as a bounded scanning service and put a
mature MTA such as Postfix at the Internet boundary. Postfix should own MX/TLS,
SMTP authentication, queueing, retries, back-pressure, recipient verification,
rate limits, anti-spam controls, and durable delivery. Integrate scanning through
a well-defined content-filter/milter boundary, run analysis in isolated workers,
store quarantine in authenticated durable storage, add role-based administration
and audit logs, pin container images, monitor queues and latency, and perform a
formal threat model and load test. The included Python gateway should remain a
local simulation rather than being promoted directly to that role.

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
