from __future__ import annotations

import argparse
import sys
import logging
from pathlib import Path

from .core.engine import AnalyzerEngine
from .core.exceptions import MODAError


def run_ui_command(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description="Start the MODA local web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=8765, help="Port to listen on")
    parser.add_argument("--no-yara", action="store_true", help="Skip YARA scanning")
    parser.add_argument("--max-size", type=int, default=100, help="Maximum file size in MB")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable request logging")
    args = parser.parse_args(argv)

    from .ui.server import run_ui

    run_ui(
        host=args.host,
        port=args.port,
        skip_yara=args.no_yara,
        max_size_mb=args.max_size,
        verbose=args.verbose,
    )

def setup_logging(verbose: bool) -> None:
    """Setup basic logging for CLI."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "ui":
        run_ui_command(sys.argv[2:])
        return

    parser = argparse.ArgumentParser(description="Malicious Office Document Analyzer (MODA)")
    parser.add_argument("file", help="Path to the document to analyze")
    parser.add_argument("-f", "--format", choices=["console", "json", "html", "pdf"], default="console", help="Report format")
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
        engine = AnalyzerEngine(skip_yara=args.no_yara, max_file_size_mb=args.max_size)
        result = engine.analyze_file(args.file)
        
        # Dispatch to appropriate reporter
        if args.format == "console":
            from .reporting.console import ConsoleReporter
            reporter = ConsoleReporter(use_color=not args.no_color)
            if args.output:
                reporter.save(result, args.output)
            else:
                reporter.generate(result)
        elif args.format == "json":
            from .reporting.json_report import JSONReporter
            reporter = JSONReporter()
            if args.output:
                reporter.save(result, args.output)
            else:
                print(reporter.generate(result))
        else:
            print(f"Format {args.format} not fully implemented yet.", file=sys.stderr)
            
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
