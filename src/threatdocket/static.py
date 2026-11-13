"""Read-only checks. Rule output contains locations and remediation, never source snippets."""
from fnmatch import fnmatchcase
import ast
import os
import re
from pathlib import Path
import stat

import yaml

EXCLUDED = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor",
            "__pycache__", "dist", "build", ".tox", ".mypy_cache", ".pytest_cache"}
SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".yaml", ".yml", ".toml", ".json", ".ini", ".cfg", ".env"}
SECRET = re.compile(
    r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{32,}|github_pat_[A-Za-z0-9_]{30,}|"
    r"AIza[A-Za-z0-9_-]{35}|(?:AKIA|ASIA)[A-Z0-9]{16})\b"
)
PEM = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")
RULES = {
    "SEC001": ("high", "REVIEW", "Credential-like value", "AML.T0055",
               "Confirm whether this is a real credential. If confirmed, revoke or rotate it and use secret storage."),
    "RUN001": ("high", "REVIEW", "Python subprocess call with shell enabled", "AML.T0050",
               "Review the input boundary. Use a fixed argument list with shell disabled for untrusted input."),
    "RUN002": ("medium", "REVIEW", "Python dynamic evaluation", "AML.T0050",
               "Review which data reaches dynamic execution and use a constrained parser for data inputs."),
    "K8S001": ("high", "FAIL", "Kubernetes container explicitly privileged", "AML.T0105",
               "Remove privileged mode and grant only the capabilities the workload needs."),
    "K8S002": ("high", "FAIL", "Kubernetes workload shares the host network", "AML.T0105",
               "Use an isolated workload network and document any required exception."),
    "K8S003": ("high", "FAIL", "Kubernetes workload mounts a host path", "AML.T0105",
               "Use a scoped volume instead of a host filesystem path."),
    "CI001": ("high", "FAIL", "GitHub Actions explicitly requests all write permissions", "AML.T0091.000",
              "Use minimal explicit workflow and job token permissions."),
    "CI002": ("high", "REVIEW", "GitHub Actions uses a privileged pull request trigger", "AML.T0055",
              "Review the workflow trust boundary and keep untrusted repository content away from secrets."),
    "CTR001": ("medium", "FAIL", "Final Docker stage explicitly runs as root", "AML.T0105",
               "Set the runtime user to a non-root identity."),
}

MAX_BYTES = 512 * 1024
MAX_FILES = 5000
MAX_FINDINGS = 3000


def read_regular(path, limit=MAX_BYTES):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ValueError("non-regular file or size limit exceeded")
        body = handle.read(limit + 1)
        if len(body) > limit:
            raise ValueError("file size limit exceeded")
        return body


def finding(rule, path, line=None):
    severity, status, title, technique, action = RULES[rule]
    return dict(rule=rule, status=status, severity=severity, title=title,
                technique=technique, path=path, line=line, action=action)


def python_findings(tree, path):
    subprocess_names, imported_functions = set(), set()
    api = {"run", "Popen", "call", "check_output", "check_call"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            subprocess_names.update(x.asname or x.name for x in node.names if x.name == "subprocess")
        if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            imported_functions.update(x.asname or x.name for x in node.names if x.name in api)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        bare = isinstance(target, ast.Name)
        if bare and target.id in {"eval", "exec"}:
            yield finding("RUN002", path, node.lineno)
        qualified = (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                     and target.value.id in subprocess_names and target.attr in api)
        if (qualified or (bare and target.id in imported_functions)) and any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        ):
            yield finding("RUN001", path, node.lineno)


def mapping(value):
    return value if isinstance(value, dict) else {}


def objects(value):
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def yaml_findings(content, path):
    # BaseLoader preserves workflow's literal "on" key and never constructs tagged objects.
    workflow = path.startswith(".github/workflows/")
    result = set()
    for doc in yaml.load_all(content, Loader=yaml.BaseLoader):
        row = mapping(doc)
        if workflow:
            jobs = objects(list(mapping(row.get("jobs")).values()))
            if any(scope.get("permissions") == "write-all" for scope in [row, *jobs]):
                result.add("CI001")
            events = row.get("on", [])
            if "pull_request_target" in (events if isinstance(events, (dict, list)) else [events]):
                result.add("CI002")
        if not row.get("apiVersion"):
            continue
        specs = mapping(row.get("spec"))
        if row.get("kind") == "Pod":
            pod = specs
        elif row.get("kind") == "CronJob":
            pod = mapping(mapping(mapping(mapping(specs.get("jobTemplate")).get("spec")).get("template")).get("spec"))
        elif row.get("kind") in {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet", "ReplicationController"}:
            pod = mapping(mapping(specs.get("template")).get("spec"))
        else:
            continue
        if str(pod.get("hostNetwork", "")).lower() in {"true", "yes", "on", "y"}:
            result.add("K8S002")
        if any("hostPath" in volume for volume in objects(pod.get("volumes"))):
            result.add("K8S003")
        if any(str(mapping(container.get("securityContext")).get("privileged", "")).lower() in {"true", "yes", "on", "y"}
               for key in ("containers", "initContainers", "ephemeralContainers") for container in objects(pod.get(key))):
            result.add("K8S001")
    return [finding(rule, path) for rule in sorted(result)]


def excluded(relative, patterns):
    """True when a POSIX relative path matches a glob pattern or sits under an excluded directory."""
    for pattern in patterns:
        pattern = pattern.strip().strip("/")
        if pattern and (fnmatchcase(relative, pattern) or relative == pattern or relative.startswith(pattern + "/")
                        or fnmatchcase(relative, pattern.removesuffix("/**"))):
            return True
    return False


def scan(root, exclude=()):
    findings, warnings = [], []
    examined = skipped = 0
    root = Path(root)

    def walk_error(_error):
        warnings.append("A directory could not be enumerated.")

    for directory, dirs, names in os.walk(root, onerror=walk_error):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not (Path(directory) / d).is_symlink()
                         and not excluded((Path(directory) / d).relative_to(root).as_posix(), exclude))
        for name in sorted(names):
            path = Path(directory) / name
            docker = name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile")
            if not docker and path.suffix.lower() not in SUFFIXES and not name.startswith(".env"):
                continue
            relative = path.relative_to(root).as_posix()
            if excluded(relative, exclude):
                continue
            if path.is_symlink() or not path.is_file():
                skipped += 1
                continue
            if examined + skipped >= MAX_FILES or len(findings) >= MAX_FINDINGS:
                warnings.append("Static scan stopped at its file or finding limit.")
                return findings[:MAX_FINDINGS], warnings, examined, skipped
            try:
                content = read_regular(path).decode("utf-8")
            except (OSError, ValueError):
                skipped += 1
                continue
            examined += 1
            try:
                for line, value in enumerate(content.splitlines(), 1):
                    if SECRET.search(value) or PEM.search(value):
                        findings.append(finding("SEC001", relative, line))
                    if len(findings) >= MAX_FINDINGS:
                        break
                if path.suffix == ".py":
                    findings.extend(python_findings(ast.parse(content), relative))
                elif path.suffix in {".yaml", ".yml"}:
                    findings.extend(yaml_findings(content, relative))
                elif docker:
                    user = None
                    for line, value in enumerate(content.splitlines(), 1):
                        parts = value.strip().split(maxsplit=1)
                        if len(parts) != 2:
                            continue
                        instruction, argument = parts
                        if instruction.upper() == "FROM":
                            user = None
                        if instruction.upper() == "USER":
                            user = line if argument.split(":", 1)[0].strip() in {"root", "0"} else None
                    if user:
                        findings.append(finding("CTR001", relative, user))
            except (SyntaxError, yaml.YAMLError, RecursionError, ValueError):
                warnings.append(f"Could not parse {relative} for structural checks.")
    if len(findings) >= MAX_FINDINGS:
        warnings.append("Static scan reached its finding limit.")
    return findings[:MAX_FINDINGS], warnings, examined, skipped
