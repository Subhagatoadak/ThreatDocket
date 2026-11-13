"""Command-line interface and CI output."""
import argparse
import json
from pathlib import Path
import sys

from .review import review


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
    args = parser.parse_args(argv)
    try:
        report = review(args.project, profile=args.profile, evidence=args.evidence, policy=args.policy)
        if args.command == "tui":
            from .tui import Dashboard

            Dashboard(report).run()
        elif args.command == "advise":
            from .advisory import advisory
            from .tui import plain

            print(plain(advisory(report)))
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
