from __future__ import annotations

import hashlib

from ..core.base import BaseAnalyzer
from ..core.context import AnalysisContext


class HashGenerator(BaseAnalyzer):
    """Computes identity hashes for the analysed artifact."""

    @property
    def name(self) -> str:
        return "HashGenerator"

    @property
    def description(self) -> str:
        return "Computes MD5, SHA1, and SHA256 hashes of the file."

    def analyze(self, context: AnalysisContext) -> None:
        data = context.file_bytes

        md5_hash = hashlib.md5(data, usedforsecurity=False).hexdigest()
        sha1_hash = hashlib.sha1(data, usedforsecurity=False).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()

        context.hashes = {"MD5": md5_hash, "SHA1": sha1_hash, "SHA256": sha256_hash}
