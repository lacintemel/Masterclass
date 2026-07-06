from __future__ import annotations

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
        self.rules = None
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
        rules_dir = get_rules_dir() / "official"
        if not rules_dir.exists():
            return
            
        filepaths = {}
        for rule_file in rules_dir.glob("*.yar"):
            filepaths[rule_file.stem] = str(rule_file)
            
        if filepaths:
            try:
                self.rules = yara.compile(filepaths=filepaths)
            except Exception as e:
                self.logger.error(f"Failed to compile YARA rules: {e}")

    def analyze(self, context: AnalysisContext) -> None:
        if not self.rules:
            return
            
        try:
            matches = self.rules.match(data=context.file_bytes)
            for m in matches:
                ym = YaraMatch(
                    rule_name=m.rule,
                    rule_namespace=m.namespace,
                    tags=m.tags,
                    strings_matched=tuple(
                        (0, str(index), str(match).encode("utf-8", errors="ignore"))
                        for index, match in enumerate(m.strings)
                    ),
                    meta=m.meta
                )
                context.add_yara_match(ym)
        except Exception as e:
            context.errors.append(f"YARA scanning error: {e}")
