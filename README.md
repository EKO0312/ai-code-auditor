# AI-Generated Code Auditor (v0.1)

A small Python tool that scans a project for risky patterns AI coding assistants often produce, and checks dependencies for packages the AI may have invented.


## What it checks

| Rule | What |
|---|---|
| AIC001 | `eval()` / `exec()` |
| AIC002 | Shell execution (`os.system`, `subprocess(..., shell=True)`) |
| AIC003 | Unsafe deserialization (`pickle`, `marshal`, `yaml.load` without a safe loader) |
| AIC004 | TLS verification disabled (`verify=False`) |
| AIC005 | Flask debug mode on |
| AIC006 | SQL built from strings (f-strings, `+`, `%`, `.format`) |
| AIC007 | Hardcoded secrets (by variable name, and known key formats) |
| AIC008 | Weak hashes (MD5, SHA-1) |
| AIC009 | Tokens made with `random` instead of `secrets` |
| AIC010 | `tempfile.mktemp` |
| AIC020 | Imported but not declared in requirements |
| AIC021 | Package name that does not exist on PyPI (possible AI-invented name) |
| AIC022 | Package first published in the last 30 days |

Findings are grouped into **fix today / this week / this month**.

## Use

```bash
python auditor.py path/to/project
python auditor.py path/to/project --offline          # skip PyPI checks
python auditor.py path/to/project --md report.md --json report.json
python auditor.py path/to/project --fail-on high     # exit 1 if any high finding (for CI)
```

Python 3.10+, standard library only.

Try the demo: `python auditor.py sample`

The `sample/` folder is deliberately vulnerable test code. Every credential in it is a fake demo value, not a real secret.

Run tests: `python -m unittest discover -s tests -v`

## CI example (GitHub Actions)

```yaml
- name: AI code audit
  run: python auditor.py . --fail-on high
```

## Limits (read these)

- Python only. Heuristic checks: expect false positives and missed issues.
- Not a full security audit. A clean report does not mean the code is secure.
- PyPI checks need a network connection and only cover package existence and age, not malware.
- Only scan code you own or have written permission to review.

