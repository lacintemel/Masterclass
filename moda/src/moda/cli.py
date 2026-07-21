from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import logging.config
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .core.engine import AnalyzerEngine
from .core.exceptions import MODAError
from .core.file_support import SUPPORTED_EXTENSIONS

if TYPE_CHECKING:
    from .core.models import AnalysisResult
    from .reporting.base import BaseReporter


def run_ui_command(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description="Start the MODA local web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=8765, help="Port to listen on")
    parser.add_argument("--no-yara", action="store_true", help="Skip YARA scanning")
    parser.add_argument("--max-size", type=int, default=100, help="Maximum file size in MB")
    parser.add_argument("--rules", help="Path to custom YARA rules directory")
    parser.add_argument("--config", help="Path to scoring YAML configuration")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable request logging")
    parser.add_argument("--allow-remote", action="store_true", help="Allow a non-loopback bind")
    parser.add_argument("--token", help="Remote UI access token (or MODA_UI_TOKEN)")
    parser.add_argument(
        "--max-concurrent", type=int, default=2, help="Maximum simultaneous analyses"
    )
    args = parser.parse_args(argv)

    from .ui.server import run_ui

    run_ui(
        host=args.host,
        port=args.port,
        skip_yara=args.no_yara,
        max_size_mb=args.max_size,
        verbose=args.verbose,
        allow_remote=args.allow_remote,
        access_token=args.token or os.environ.get("MODA_UI_TOKEN"),
        max_concurrent_analyses=args.max_concurrent,
        rules_dir=args.rules,
        scoring_config=args.config,
    )


def run_batch_command(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description="Analyze a directory of documents")
    parser.add_argument("path", help="Directory or file to analyze")
    parser.add_argument(
        "-o", "--output", default="moda_batch_results.jsonl", help="JSONL output path"
    )
    parser.add_argument("--recursive", action="store_true", help="Recurse into subdirectories")
    parser.add_argument("--no-yara", action="store_true", help="Skip YARA scanning")
    parser.add_argument("--max-size", type=int, default=100, help="Maximum file size in MB")
    parser.add_argument("--rules", help="Path to custom YARA rules directory")
    parser.add_argument("--config", help="Path to scoring YAML configuration")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    target = Path(args.path)
    files = discover_input_files(target, recursive=args.recursive)
    engine = AnalyzerEngine(
        skip_yara=args.no_yara,
        max_file_size_mb=args.max_size,
        rules_dir=args.rules,
        scoring_config=args.config,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary = {"total": len(files), "analyzed": 0, "errors": 0, "high_or_critical": 0}

    with output_path.open("w", encoding="utf-8") as handle:
        for file_path in files:
            try:
                result = engine.analyze_file(file_path)
                payload = result.to_dict()
                summary["analyzed"] += 1
                if result.risk_level in {"high", "critical"}:
                    summary["high_or_critical"] += 1
            except Exception as exc:
                payload = {
                    "file_info": {"file_path": str(file_path), "file_name": file_path.name},
                    "error": str(exc),
                }
                summary["errors"] += 1
            handle.write(json.dumps(payload, default=str, sort_keys=True) + "\n")

    print(
        "Batch complete: "
        f"{summary['analyzed']}/{summary['total']} analyzed, "
        f"{summary['high_or_critical']} high/critical, "
        f"{summary['errors']} errors"
    )
    print(f"Results saved to {output_path}")


def run_doctor_command(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description="Check MODA runtime readiness")
    parser.parse_args(argv)

    from .utils.config_loader import get_config_dir, get_rules_dir

    checks = [
        ("Python >= 3.10", sys.version_info >= (3, 10), sys.version.split()[0]),
        ("Config directory", get_config_dir().exists(), str(get_config_dir())),
        ("Rules directory", get_rules_dir().exists(), str(get_rules_dir())),
        (
            "UI assets",
            (Path(__file__).parent / "ui" / "static" / "index.html").exists(),
            "static UI",
        ),
    ]
    optional_modules = {
        "python-magic": "magic",
        "olefile": "olefile",
        "oletools": "oletools",
        "yara-python": "yara",
        "pypdf": "pypdf",
        "rich": "rich",
        "pyyaml": "yaml",
    }
    for label, module_name in optional_modules.items():
        checks.append((label, importlib.util.find_spec(module_name) is not None, module_name))

    failed_required = False
    for label, ok, detail in checks:
        status = "OK" if ok else "MISSING"
        print(f"{status:8} {label} ({detail})")
        if (
            label in {"Python >= 3.10", "Config directory", "Rules directory", "UI assets"}
            and not ok
        ):
            failed_required = True

    if failed_required:
        raise SystemExit(1)


def discover_input_files(path: Path, *, recursive: bool = False) -> list[Path]:
    """Find supported document files for batch analysis."""
    if path.is_file():
        return [path] if path.suffix.lower() in SUPPORTED_EXTENSIONS else []
    if not path.exists():
        raise FileNotFoundError(f"Path not found: {path}")
    if not path.is_dir():
        raise FileNotFoundError(f"Not a file or directory: {path}")

    iterator = path.rglob("*") if recursive else path.glob("*")
    return sorted(
        file_path
        for file_path in iterator
        if file_path.is_file() and file_path.suffix.lower() in SUPPORTED_EXTENSIONS
    )


def setup_logging(verbose: bool) -> None:
    """Configure logging from packaged YAML with a safe fallback."""
    try:
        from .utils.config_loader import get_config_dir, load_yaml_config

        config = load_yaml_config(get_config_dir() / "logging.yaml")
        console_level = "DEBUG" if verbose else "WARNING"
        config.setdefault("handlers", {}).setdefault("console", {})["level"] = console_level
        config.setdefault("loggers", {}).setdefault("moda", {})["level"] = console_level
        logging.config.dictConfig(config)
    except Exception:
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.WARNING,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )


def build_reporter(format_name: str, *, use_color: bool = True) -> BaseReporter:
    """Create a reporter for a CLI format name."""
    if format_name == "console":
        from .reporting.console import ConsoleReporter

        return ConsoleReporter(use_color=use_color)
    if format_name == "json":
        from .reporting.json_report import JSONReporter

        return JSONReporter()
    if format_name == "html":
        from .reporting.html_report import HTMLReporter

        return HTMLReporter()
    if format_name == "pdf":
        from .reporting.pdf_report import PDFReporter

        return PDFReporter()
    raise ValueError(f"Unsupported report format: {format_name}")


def emit_report(
    result: AnalysisResult,
    reporter: BaseReporter,
    *,
    output: str | None,
    force_file: bool = False,
) -> None:
    """Print or save a generated report."""
    if output:
        reporter.save(result, output)
        print(f"Report saved to {output}")
        return

    if force_file:
        output_path = reporter.get_default_filename(result)
        reporter.save(result, output_path)
        print(f"Report saved to {output_path}")
        return

    payload = reporter.generate(result)
    if isinstance(payload, bytes):
        sys.stdout.buffer.write(payload)
    elif payload:
        print(payload)


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "ui":
        run_ui_command(sys.argv[2:])
        return
    if len(sys.argv) > 1 and sys.argv[1] == "batch":
        run_batch_command(sys.argv[2:])
        return
    if len(sys.argv) > 1 and sys.argv[1] == "doctor":
        run_doctor_command(sys.argv[2:])
        return

    parser = argparse.ArgumentParser(
        description="Malicious Office Document Analyzer (MODA)",
        epilog=(
            "Commands: moda ui | moda batch <path> | moda doctor. "
            "Use '<command> --help' for command-specific options."
        ),
    )
    parser.add_argument("file", help="Path to the document to analyze")
    parser.add_argument(
        "-f",
        "--format",
        choices=["console", "json", "html", "pdf"],
        default="console",
        help="Report format",
    )
    parser.add_argument("-o", "--output", help="Output file path for report")
    parser.add_argument("-r", "--rules", help="Path to custom YARA rules directory")
    parser.add_argument("-c", "--config", help="Path to custom config file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-yara", action="store_true", help="Skip YARA scanning")
    parser.add_argument("--no-color", action="store_true", help="Disable colored console output")
    parser.add_argument("--max-size", type=int, default=100, help="Maximum file size in MB")

    args = parser.parse_args()
    setup_logging(args.verbose)

    try:
        engine = AnalyzerEngine(
            skip_yara=args.no_yara,
            max_file_size_mb=args.max_size,
            rules_dir=args.rules,
            scoring_config=args.config,
        )
        result = engine.analyze_file(args.file)

        reporter = build_reporter(args.format, use_color=not args.no_color)
        emit_report(
            result,
            reporter,
            output=args.output,
            force_file=args.format in {"html", "pdf"} and args.output is None,
        )

        if args.format == "console":
            print("Analysis completed successfully.")

    except MODAError as e:
        print(f"MODA Analysis Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()
