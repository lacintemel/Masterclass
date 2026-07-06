# External YARA Rules

Place third-party YARA rulesets here when you want MODA to scan with community
or vendor-maintained detections in addition to the built-in official rules.

MODA recursively loads:

- `rules/official/**/*.yar`
- `rules/custom/**/*.yar`
- `rules/external/**/*.yar`
- `rules/community/**/*.yar`

Recommended layout:

```text
rules/external/
  signature-base/
    yara/
      *.yar
  yara-forge/
    *.yar
  elastic/
    *.yar
  yara-rules/
    *.yar
```

Notes:

- Review each source license before committing or redistributing rules.
- Large public rulesets can be noisy on document-only triage workloads.
- Some third-party rules require external variables or YARA modules. MODA skips
  files that fail compilation and records compile errors in the report.
- Keep production rules pinned to a commit or release so results are repeatable.
