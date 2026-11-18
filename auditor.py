#!/usr/bin/env python3
"""AI-Generated Code Auditor v0.1

Scans a Python project for risky patterns that AI coding assistants often produce,
and checks dependencies for packages that may have been invented by the AI
(a supply-chain risk sometimes called "slopsquatting").

Usage:
    python auditor.py PATH [--offline] [--md report.md] [--json report.json] [--fail-on high]

Only scan code you own or have written permission to review.
Heuristic tool: expect false positives and misses. It is a first pass, not an audit.
"""
import argparse
import ast
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "site-packages", "dist", "build"}
TEXT_EXT = {".py", ".env", ".json", ".yml", ".yaml", ".txt", ".cfg", ".ini", ".toml"}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
HORIZON_BY_SEVERITY = {"high": "today", "medium": "this week", "low": "this month"}

SECRET_NAME = re.compile(r"(api[_-]?key|secret|token|passw(or)?d|passwd|private[_-]?key)", re.I)
PLACEHOLDER = re.compile(r"(your|example|changeme|xxx|<.*>|\$\{|placeholder|dummy|replace|todo)", re.I)
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("OpenAI-style API key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

# import name -> distribution name, for common mismatches
IMPORT_ALIASES = {
    "yaml": "pyyaml", "PIL": "pillow", "cv2": "opencv-python", "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4", "dotenv": "python-dotenv", "jwt": "pyjwt", "dateutil": "python-dateutil",
    "flask_cors": "flask-cors", "flask_sqlalchemy": "flask-sqlalchemy", "flask_login": "flask-login",
    "flask_wtf": "flask-wtf", "flask_migrate": "flask-migrate", "Crypto": "pycryptodome",
    "psycopg2": "psycopg2-binary", "MySQLdb": "mysqlclient", "serial": "pyserial", "magic": "python-magic",
}


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    message: str
    fix: str

    @property
    def horizon(self):
        return HORIZON_BY_SEVERITY[self.severity]


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def kwarg(call, name):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def is_const(node, value):
    return isinstance(node, ast.Constant) and node.value is value


def looks_dynamic_sql(arg):
    if isinstance(arg, ast.JoinedStr):
        return True
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
        return True
    return False


class Visitor(ast.NodeVisitor):
    def __init__(self, path):
        self.path = path
        self.findings = []

    def add(self, node, rule, severity, message, fix):
        self.findings.append(Finding(rule, severity, self.path, getattr(node, "lineno", 0), message, fix))

    def visit_Call(self, node):
        name = dotted(node.func)
        if name in ("eval", "exec"):
            self.add(node, "AIC001", "high", f"{name}() runs arbitrary code.",
                     "Remove it. Parse data with json/ast.literal_eval or use an explicit lookup table.")
        if name == "os.system" or (name.startswith("subprocess.") and is_const(kwarg(node, "shell"), True)):
            self.add(node, "AIC002", "high", "Shell command execution; user input could inject commands.",
                     "Use subprocess.run([...], shell=False) with a fixed argument list.")
        if name in ("pickle.load", "pickle.loads", "marshal.loads", "dill.loads"):
            self.add(node, "AIC003", "high", f"{name} can execute code from untrusted data.",
                     "Use JSON or another data-only format for anything that crosses a trust boundary.")
        if name == "yaml.load":
            loader = kwarg(node, "Loader")
            if loader is None or "Safe" not in dotted(loader):
                self.add(node, "AIC003", "high", "yaml.load without a safe loader can run code.",
                         "Use yaml.safe_load().")
        if name.startswith("requests.") and is_const(kwarg(node, "verify"), False):
            self.add(node, "AIC004", "medium", "TLS certificate verification is turned off.",
                     "Remove verify=False. Fix the certificate problem instead.")
        if name.endswith(".run") and is_const(kwarg(node, "debug"), True):
            self.add(node, "AIC005", "high", "Debug mode enabled; the Flask debugger can allow code execution.",
                     "Set debug=False in production and read it from an environment variable.")
        if name.endswith((".execute", ".executemany")) and node.args and looks_dynamic_sql(node.args[0]):
            self.add(node, "AIC006", "high", "SQL query built from a string; likely SQL injection.",
                     "Use parameterized queries: cursor.execute('... WHERE id = %s', (value,)).")
        if name in ("hashlib.md5", "hashlib.sha1"):
            self.add(node, "AIC008", "medium", f"{name} is weak; unsafe for passwords or signatures.",
                     "Use bcrypt, argon2 or scrypt for passwords, and SHA-256 or better for integrity.")
        if name == "tempfile.mktemp":
            self.add(node, "AIC010", "low", "tempfile.mktemp is race-prone.", "Use tempfile.mkstemp or NamedTemporaryFile.")
        self.generic_visit(node)

    def _check_assign(self, node, targets, value):
        if value is None:
            return
        for t in targets:
            tname = t.id if isinstance(t, ast.Name) else (t.attr if isinstance(t, ast.Attribute) else "")
            if not tname:
                continue
            if (SECRET_NAME.search(tname) and isinstance(value, ast.Constant)
                    and isinstance(value.value, str) and len(value.value) >= 8
                    and not PLACEHOLDER.search(value.value)):
                self.add(node, "AIC007", "high", f"Hardcoded secret in '{tname}'.",
                         "Move it to an environment variable or secrets manager, then rotate the exposed value.")
            if re.search(r"(token|otp|password|secret)", tname, re.I):
                for sub in ast.walk(value):
                    if isinstance(sub, ast.Call) and dotted(sub.func).startswith("random."):
                        self.add(node, "AIC009", "medium", f"'{tname}' generated with the random module, which is predictable.",
                                 "Use the secrets module (secrets.token_urlsafe).")
                        break

    def visit_Assign(self, node):
        self._check_assign(node, node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        self._check_assign(node, [node.target], node.value)
        self.generic_visit(node)


def iter_files(root, exts):
    root = Path(root)
    if root.is_file():
        yield root
        return
    for p in root.rglob("*"):
        if p.is_file() and not (set(p.relative_to(root).parts[:-1]) & SKIP_DIRS) and (p.suffix in exts or p.name == ".env"):
            yield p


def scan_python(root):
    findings, imports = [], {}
    for p in iter_files(root, {".py"}):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except SyntaxError as e:
            findings.append(Finding("AIC000", "low", str(p), e.lineno or 0, "File could not be parsed.", "Fix the syntax error so it can be scanned."))
            continue
        v = Visitor(str(p))
        v.visit(tree)
        findings += v.findings
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    imports.setdefault(a.name.split(".")[0], (str(p), n.lineno))
            elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
                imports.setdefault(n.module.split(".")[0], (str(p), n.lineno))
    return findings, imports


def scan_secrets(root):
    findings = []
    for p in iter_files(root, TEXT_EXT):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for label, rx in SECRET_PATTERNS:
                if rx.search(line):
                    findings.append(Finding("AIC007", "high", str(p), i, f"Possible {label} in file.",
                                            "Remove it, rotate the key, and load it from the environment."))
    return findings


def parse_requirements(root):
    declared = {}
    for p in Path(root).rglob("requirements*.txt") if Path(root).is_dir() else []:
        if set(p.parts) & SKIP_DIRS:
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            line = line.split("#")[0].strip()
            if not line or line.startswith(("-", "git+", "http")):
                continue
            m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", line)
            if m:
                declared.setdefault(normalize(m.group(1)), (str(p), i))
    return declared


_cache = {}


def pypi_lookup(name, timeout=6):
    """Returns ('ok', first_release_datetime|None), ('missing', None) or ('error', None)."""
    if name in _cache:
        return _cache[name]
    url = f"https://pypi.org/pypi/{name}/json"
    result = ("error", None)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            data = json.load(r)
        times = []
        for files in data.get("releases", {}).values():
            for f in files:
                t = f.get("upload_time_iso_8601")
                if t:
                    times.append(datetime.fromisoformat(t.replace("Z", "+00:00")))
        result = ("ok", min(times) if times else None)
    except urllib.error.HTTPError as e:
        result = ("missing", None) if e.code == 404 else ("error", None)
    except Exception:
        result = ("error", None)
    _cache[name] = result
    return result


def local_modules(root):
    root = Path(root)
    base = root if root.is_dir() else root.parent
    names = set()
    for p in base.rglob("*"):
        if set(p.relative_to(base).parts) & SKIP_DIRS:
            continue
        if p.suffix == ".py":
            names.add(p.stem)
        elif p.is_dir() and (p / "__init__.py").exists():
            names.add(p.name)
    return names


def scan_dependencies(root, imports, offline):
    findings, notes = [], []
    declared = parse_requirements(root)
    local = local_modules(root)
    stdlib = set(sys.stdlib_module_names)
    new_days = 30
    unverifiable = False

    for name, (path, line) in declared.items():
        if offline:
            continue
        status, first = pypi_lookup(name)
        if status == "missing":
            findings.append(Finding("AIC021", "high", path, line,
                                    f"'{name}' does not exist on PyPI. AI tools sometimes invent package names, and attackers can register them.",
                                    "Remove it or replace it with the real package, then check how it got into the file."))
        elif status == "ok" and first and (datetime.now(timezone.utc) - first).days < new_days:
            findings.append(Finding("AIC022", "medium", path, line,
                                    f"'{name}' was first published {(datetime.now(timezone.utc) - first).days} days ago.",
                                    "Check the maintainer, source repo and download history before trusting it."))
        elif status == "error":
            unverifiable = True

    for mod, (path, line) in imports.items():
        if mod in stdlib or mod in local or mod == "__future__":
            continue
        dist = normalize(IMPORT_ALIASES.get(mod, mod))
        if dist in declared:
            continue
        findings.append(Finding("AIC020", "low", path, line,
                                f"'{mod}' is imported but not declared in requirements.",
                                "Add it to requirements.txt with a pinned version, or remove the import."))
        if not offline:
            status, _ = pypi_lookup(dist)
            if status == "missing":
                findings.append(Finding("AIC021", "high", path, line,
                                        f"Import '{mod}' matches no PyPI package. It may be invented or a private module.",
                                        "Confirm where this module comes from before installing anything with that name."))
            elif status == "error":
                unverifiable = True
    if offline:
        notes.append("Offline mode: PyPI existence checks were skipped.")
    elif unverifiable:
        notes.append("Some packages could not be checked against PyPI (network error). Re-run with a connection.")
    return findings, notes


def render_markdown(findings, notes, target):
    out = [f"# AI Code Audit: {target}", ""]
    counts = {s: sum(1 for f in findings if f.severity == s) for s in ("high", "medium", "low")}
    out.append(f"**{len(findings)} findings** ({counts['high']} high, {counts['medium']} medium, {counts['low']} low)")
    out.append("")
    for horizon, title in (("today", "Fix today"), ("this week", "Fix this week"), ("this month", "Fix this month")):
        items = [f for f in findings if f.horizon == horizon]
        if not items:
            continue
        out += [f"## {title}", ""]
        for f in sorted(items, key=lambda x: (x.file, x.line)):
            out.append(f"- **[{f.severity.upper()}] {f.rule}** `{f.file}:{f.line}`: {f.message}")
            out.append(f"  - Fix: {f.fix}")
        out.append("")
    if not findings:
        out += ["No findings. That does not mean the code is secure; this scanner only checks a small set of patterns.", ""]
    for n in notes:
        out.append(f"> {n}")
    out.append("> Heuristic scan. Expect false positives and misses. Not a substitute for a full review.")
    return "\n".join(out) + "\n"


def audit(path, offline=False):
    findings, imports = scan_python(path)
    findings += scan_secrets(path)
    dep_findings, notes = scan_dependencies(path, imports, offline)
    findings += dep_findings
    seen, unique = set(), []
    for f in findings:
        key = (f.rule, f.file, f.line, f.message)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique, notes


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit AI-generated Python code.")
    ap.add_argument("path")
    ap.add_argument("--offline", action="store_true", help="skip PyPI checks")
    ap.add_argument("--md", help="write markdown report to this file")
    ap.add_argument("--json", help="write JSON report to this file")
    ap.add_argument("--fail-on", choices=["low", "medium", "high"], default="high",
                    help="exit with code 1 if a finding at or above this severity exists")
    args = ap.parse_args(argv)

    if not Path(args.path).exists():
        print(f"Path not found: {args.path}", file=sys.stderr)
        return 2
    findings, notes = audit(args.path, args.offline)
    report = render_markdown(findings, notes, args.path)
    print(report)
    if args.md:
        Path(args.md).write_text(report, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps([dict(asdict(f), horizon=f.horizon) for f in findings], indent=2), encoding="utf-8")
    threshold = SEVERITY_RANK[args.fail_on]
    return 1 if any(SEVERITY_RANK[f.severity] >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
