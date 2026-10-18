"""Static bug scanner: safely unzips an uploaded project and looks for
common bugs, security problems and code smells. No code is ever executed."""
import ast
import os
import re
import zipfile

MAX_FILES = 3000
MAX_TOTAL_BYTES = 100 * 1024 * 1024      # 100 MB uncompressed
MAX_FILE_BYTES = 1 * 1024 * 1024          # skip files > 1 MB when scanning
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__",
             "dist", "build", ".idea", ".vscode", "vendor", "migrations"}
TEXT_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".php", ".java",
            ".c", ".cpp", ".cs", ".go", ".rb", ".sql", ".env", ".cfg", ".ini", ".yml", ".yaml"}


def safe_extract(zip_path, dest):
    """Extract a zip while blocking zip-slip and zip-bombs."""
    total = 0
    with zipfile.ZipFile(zip_path) as z:
        infos = z.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError("Zip has too many files (limit %d)." % MAX_FILES)
        for info in infos:
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("Zip is too large when extracted (limit 100 MB).")
            target = os.path.realpath(os.path.join(dest, info.filename))
            if not target.startswith(os.path.realpath(dest) + os.sep):
                raise ValueError("Unsafe path in zip: %s" % info.filename)
        z.extractall(dest)


# (rule_id, regex, severity, title, description, suggestion)
LINE_RULES = [
    ("hardcoded-secret",
     re.compile(r"""(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['"][^'"\s]{4,}['"]"""),
     "High", "Hardcoded credential",
     "A password/secret/API key appears to be written directly in the source.",
     "Move it to an environment variable or config file that is not committed."),
    ("sql-injection",
     re.compile(r"""(?i)(execute|query)\s*\(\s*(f['"]|['"].*(select|insert|update|delete).*['"]\s*(\+|%)|.*\.format\()"""),
     "Critical", "Possible SQL injection",
     "A SQL query is built with string concatenation/formatting.",
     "Use parameterized queries (e.g. cursor.execute(sql, (value,)))."),
    ("eval-exec",
     re.compile(r"\b(eval|exec)\s*\("),
     "High", "Use of eval/exec",
     "eval/exec can run arbitrary code if any input reaches it.",
     "Replace with ast.literal_eval / json.loads or explicit logic."),
    ("debug-enabled",
     re.compile(r"debug\s*=\s*True"),
     "Medium", "Debug mode enabled",
     "Debug mode exposes stack traces and an interactive console in production.",
     "Read debug flag from an environment variable and default to False."),
    ("tls-verify-off",
     re.compile(r"verify\s*=\s*False"),
     "High", "TLS verification disabled",
     "Certificate checking is turned off, allowing man-in-the-middle attacks.",
     "Remove verify=False or point it to a trusted CA bundle."),
    ("weak-hash",
     re.compile(r"(?i)\b(md5|sha1)\s*\("),
     "Medium", "Weak hash function",
     "MD5/SHA1 are broken for security purposes such as passwords.",
     "Use bcrypt/argon2/PBKDF2 for passwords, SHA-256+ for integrity."),
    ("js-innerhtml",
     re.compile(r"\.innerHTML\s*=|document\.write\s*\("),
     "Medium", "Possible XSS sink",
     "Writing raw strings to innerHTML/document.write can allow script injection.",
     "Use textContent or sanitize the value first."),
    ("none-compare",
     re.compile(r"[=!]=\s*None\b"),
     "Low", "Comparison to None with ==/!=",
     "Comparing to None should use identity.",
     "Use 'is None' / 'is not None'."),
    ("todo-marker",
     re.compile(r"(?i)#\s*(TODO|FIXME|HACK|XXX)\b|//\s*(TODO|FIXME|HACK|XXX)\b"),
     "Low", "Unresolved TODO/FIXME",
     "Unfinished work was left in the code.",
     "Resolve it or convert it into a tracked bug."),
]


def _python_ast_findings(rel, source):
    out = []
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [dict(file=rel, line=e.lineno or 1, rule="syntax-error", severity="Critical",
                     title="Syntax error", description="File cannot be parsed: %s" % e.msg,
                     suggestion="Fix the syntax; this file will crash on import.")]
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                out.append(dict(file=rel, line=node.lineno, rule="bare-except", severity="Medium",
                                title="Bare except clause",
                                description="'except:' hides every error, including KeyboardInterrupt.",
                                suggestion="Catch specific exceptions and log them."))
            elif len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                out.append(dict(file=rel, line=node.lineno, rule="swallowed-exception", severity="Medium",
                                title="Exception silently ignored",
                                description="The except block only does 'pass', so failures go unnoticed.",
                                suggestion="Log the error or handle it properly."))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.args.defaults + [x for x in node.args.kw_defaults if x]:
                if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                    out.append(dict(file=rel, line=node.lineno, rule="mutable-default", severity="Medium",
                                    title="Mutable default argument in '%s'" % node.name,
                                    description="A list/dict/set default is shared between calls.",
                                    suggestion="Use None as the default and create the object inside the function."))
    return out


def scan_project(root):
    """Return (files_scanned, findings). Each finding is a dict."""
    findings, scanned = [], 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in TEXT_EXT:
                continue
            path = os.path.join(dirpath, fn)
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
            except OSError:
                continue
            scanned += 1
            if ext == ".py":
                findings += _python_ast_findings(rel, source)
            for lineno, line in enumerate(source.splitlines(), 1):
                for rule, rx, sev, title, desc, fix in LINE_RULES:
                    if rule == "none-compare" and ext != ".py":
                        continue
                    if rx.search(line):
                        findings.append(dict(file=rel, line=lineno, rule=rule, severity=sev,
                                             title=title, description=desc, suggestion=fix))
    return scanned, findings


PRIORITY = {"Critical": "Urgent", "High": "High", "Medium": "Medium", "Low": "Low"}
ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def group_findings(findings):
    """One bug per (rule, file) so a single issue repeated 40 times isn't 40 bugs."""
    groups = {}
    for f in findings:
        groups.setdefault((f["rule"], f["file"]), []).append(f)
    result = []
    for (rule, file), items in groups.items():
        first = items[0]
        lines = sorted({i["line"] for i in items})
        result.append(dict(
            title="[Auto] %s in %s" % (first["title"], file),
            severity=first["severity"], priority=PRIORITY[first["severity"]],
            description="%s\n\nFile: %s\nLine(s): %s\n\nSuggested fix: %s" % (
                first["description"], file, ", ".join(map(str, lines[:20])), first["suggestion"]),
            steps="1. Open %s\n2. Go to line %d\n3. Review the flagged code" % (file, lines[0]),
            file=file, rule=rule, count=len(lines)))
    result.sort(key=lambda g: ORDER[g["severity"]])
    return result
