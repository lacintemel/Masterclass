from __future__ import annotations

from pathlib import Path

try:
    import yara
except ImportError:  # pragma: no cover - optional analyzer dependency
    yara = None

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext
from ..core.models import YaraMatch
from ..utils.config_loader import get_rules_dir

class YaraScanner(BaseAnalyzer):
    def __init__(self):
        super().__init__()
        self.rules: list[tuple[str, object]] = []
        self.compile_errors: list[str] = []
        self._compile_rules()

    @property
    def name(self) -> str:
        return "YaraScanner"
        
    @property
    def description(self) -> str:
        return "Scans document against YARA rules."

    def _compile_rules(self) -> None:
        if yara is None:
            self.logger.info("YARA scanning disabled: yara-python is not installed")
            return
        rules_root = get_rules_dir()
        if not rules_root.exists():
            return

        for rule_file in self._iter_rule_files(rules_root):
            namespace = self._namespace_for(rule_file, rules_root)
            try:
                compiled = yara.compile(filepaths={namespace: str(rule_file)})
            except Exception as e:
                error = f"{rule_file}: {e}"
                self.compile_errors.append(error)
                self.logger.error("Failed to compile YARA rule file: %s", error)
                continue
            self.rules.append((namespace, compiled))

    def _iter_rule_files(self, rules_root: Path) -> list[Path]:
        rule_files: list[Path] = []
        for rules_dir in (
            rules_root / "official",
            rules_root / "custom",
            rules_root / "external",
            rules_root / "community",
        ):
            if not rules_dir.exists():
                continue
            rule_files.extend(sorted(rules_dir.rglob("*.yar")))
            rule_files.extend(sorted(rules_dir.rglob("*.yara")))
        return sorted(set(rule_files))

    def _namespace_for(self, rule_file: Path, rules_root: Path) -> str:
        relative = rule_file.relative_to(rules_root)
        raw = "_".join(relative.with_suffix("").parts)
        return "".join(char if char.isalnum() or char == "_" else "_" for char in raw)

    def analyze(self, context: AnalysisContext) -> None:
        if not self.rules:
            if self.compile_errors:
                context.errors.extend(f"YARA compile error: {error}" for error in self.compile_errors)
            return

        if self.compile_errors:
            context.extra["yara_compile_errors"] = list(self.compile_errors)

        try:
            for namespace, rules in self.rules:
                matches = rules.match(data=context.file_bytes)
                for m in matches:
                    ym = YaraMatch(
                        rule_name=m.rule,
                        rule_namespace=m.namespace or namespace,
                        tags=m.tags,
                        strings_matched=tuple(
                            (0, str(index), str(match).encode("utf-8", errors="ignore"))
                            for index, match in enumerate(m.strings)
                        ),
                        meta=m.meta
                    )
                    context.add_yara_match(ym)
                    self._add_finding(
                        context,
                        title=f"YARA Rule Match: {ym.rule_name}",
                        description=f"File matched YARA rule '{ym.rule_name}' from namespace '{ym.rule_namespace}'.",
                        severity=ym.severity_hint,
                        details={
                            "rule_name": ym.rule_name,
                            "rule_namespace": ym.rule_namespace,
                            "tags": list(ym.tags),
                            "meta": ym.meta,
                            "strings_matched_count": len(ym.strings_matched),
                            "match_hash": ym.match_hash,
                        },
                    )
        except Exception as e:
            context.errors.append(f"YARA scanning error: {e}")
