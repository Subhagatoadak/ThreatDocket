"""Command-line interface and CI output."""
import argparse
import json
from pathlib import Path
import sys

PROVIDER_CHOICES = ("openai", "anthropic", "gemini", "compatible")


def _llm_args(cmd):
    cmd.add_argument("--provider", choices=PROVIDER_CHOICES, help="Model provider (default: saved or openai)")
    cmd.add_argument("--model", help="Model name (required unless saved; check-llm lists the models your key can use)")
    cmd.add_argument("--base-url", help="Override the provider base URL (proxy, gateway, self-hosted)")


def _progress_printer(stream):
    icons = {"ok": "✓", "warn": "!", "fail": "✗"}

    def report(index, total, label, status, detail):
        if status == "run":
            return
        width = 20
        filled = round(width * (index + 1) / total)
        bar = "█" * filled + "░" * (width - filled)
        line = f"[{bar}] {index + 1}/{total} {icons[status]} {label}"
        if detail:
            line += f" — {detail}"
        print(line, file=stream, flush=True)

    return report


def main(argv=None):
    parser = argparse.ArgumentParser(prog="threatdocket", description="Local AI threat analysis and control review")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("tui", "Open the terminal dashboard"),
        ("scan", "Write an assessment as JSON"),
        ("advise", "Request an optional model explanation of aggregate results"),
    ):
        cmd = commands.add_parser(name, help=help_text)
        cmd.add_argument("project", type=Path, nargs="?", default=Path.cwd())
        for argument in ("profile", "evidence", "policy"):
            cmd.add_argument("--" + argument, type=Path)
        if name == "scan":
            cmd.add_argument("--output", type=Path, help="Write to a new report file")
            cmd.add_argument("--fail-on-findings", action="store_true",
                             help="Return exit code 1 for static FAIL findings or attested control failures")
        if name == "advise":
            _llm_args(cmd)
    check = commands.add_parser("check-llm", help="Verify model provider settings, API key and connectivity")
    _llm_args(check)
    args = parser.parse_args(argv)
    try:
        if args.command == "check-llm":
            from .advisory import check_connection, resolve_config

            config = resolve_config(args.provider, args.model, args.base_url)
            ok, _models = check_connection(config, _progress_printer(sys.stdout))
            print("All checks passed" if ok else "Check failed", file=sys.stdout if ok else sys.stderr)
            return 0 if ok else 1
        from .review import review

        report = review(args.project, profile=args.profile, evidence=args.evidence, policy=args.policy)
        if args.command == "tui":
            from .tui import Dashboard

            Dashboard(report).run()
        elif args.command == "advise":
            from .advisory import advisory, resolve_config
            from .tui import plain

            config = resolve_config(args.provider, args.model, args.base_url)
            print(plain(advisory(report, config, _progress_printer(sys.stderr))))
        else:
            result = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
            if args.output:
                with args.output.open("x", encoding="utf-8") as handle:
                    handle.write(result)
            else:
                print(result, end="")
            if args.fail_on_findings and (report["summary"]["findings"].get("FAIL")
                                          or report["summary"]["controls"].get("ATTESTED_FAIL")):
                return 1
    except (OSError, ValueError) as error:
        from .tui import plain

        print("threatdocket: " + plain(error), file=sys.stderr)
        return 2
    return 0
