"""Terminal dashboard for local findings and MITRE ATLAS reference data."""
import re

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import DataTable, Footer, Header, Input, Static, TabbedContent, TabPane

from .review import catalog

COLUMNS = {
    "findings": ("Rule", "Status", "Severity", "Finding", "Location"),
    "controls": ("Control", "Status", "Surface", "Title"),
    "cases": ("ATLAS ID", "Type", "Case"),
    "techniques": ("ATLAS ID", "Technique or sub-technique", "Local controls", "Cases"),
    "mitigations": ("ATLAS ID", "Mitigation", "Techniques"),
    "tactics": ("ATLAS ID", "Tactic", "Techniques"),
}


def plain(value):
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]", "", str(value))


def section(title, *items):
    return "\n\n" + title + "\n" + "\n".join(str(item) for item in items if item)


class Dashboard(App):
    TITLE = "THREATDOCKET"
    BINDINGS = [("q", "quit", "Quit")]
    CSS = """
    Screen { background: $surface; }
    Header { background: $primary-background; }
    Footer { background: $panel; }
    #overview { height: auto; padding: 1 2; background: $panel; }
    TabbedContent { height: 1fr; }
    TabPane { padding: 0 1; }
    Input { height: 3; margin: 0 0 1 0; }
    .split { height: 1fr; }
    .table { width: 3fr; min-width: 24; height: 1fr; }
    .detail-scroll { width: 2fr; min-width: 18; padding: 0 1; border-left: solid $primary; }
    .detail { height: auto; }
    """

    def __init__(self, report):
        super().__init__()
        self.report = report
        self.atlas = catalog()
        self.rows = self._rows()
        self.filtered_rows = {}

    def _rows(self):
        atlas = self.atlas
        controls = self.report["controls"]
        coverage = self.report["technique_coverage"]

        def labels(ids, names):
            return [f"{key}  {names[key]}" for key in ids]

        technique_names = {
            key: ((atlas["techniques"][value["parent"]]["name"] + " / ") if value["parent"] else "")
            + value["name"] for key, value in atlas["techniques"].items()
        }
        mitigation_names = {key: value["name"] for key, value in atlas["mitigations"].items()}
        rows = {key: [] for key in COLUMNS}
        for row in self.report["findings"]:
            location = row["path"] + (f":{row['line']}" if row["line"] else "")
            values = (row["rule"], row["status"], row["severity"], row["title"], location)
            detail = row["title"] + section("Location", location) + section("Recommended action", row["action"])
            detail += section("ATLAS reference", *labels([row["technique"]], technique_names))
            detail += section("Related cases", ", ".join(row["cases"]) or "No direct references")
            rows["findings"].append((values, detail))
        for row in controls:
            values = (row["id"], row["status"], row["feature"], row["title"])
            detail = row["title"] + section("Applicability", row["applicability"])
            detail += section("Evidence required", row["evidence"])
            detail += section("Supplied evidence reference", row["reference"] or "No evidence supplied")
            detail += section("ATLAS techniques", *labels(row["techniques"], technique_names))
            detail += section("Related cases", ", ".join(row["cases"]) or "No direct references")
            rows["controls"].append((values, detail))
        for row in atlas["cases"]:
            values = (row["id"], row["type"], row["name"])
            detail = row["name"] + section("ATLAS record", row["id"], row["type"], row["date"], row["target"])
            detail += section("Summary", row["summary"])
            detail += section("Proposed check · " + row["surface"], row["check"])
            detail += section("Evidence to collect", row["evidence"])
            detail += section("ATLAS tactics", *labels(row["tactics"], atlas["tactics"]))
            detail += section("ATLAS techniques", *labels(row["techniques"], technique_names))
            detail += section("Linked mitigations", *labels(row["mitigations"], mitigation_names))
            detail += section("Source", f"https://atlas.mitre.org/studies/{row['id']}")
            rows["cases"].append((values, detail))
        for key, row in atlas["techniques"].items():
            mapping = coverage[key]
            values = (key, technique_names[key], str(len(mapping["control_ids"])), str(len(mapping["case_ids"])))
            detail = technique_names[key] + section("ATLAS technique", key)
            detail += section("Tactics", *labels(row["tactics"], atlas["tactics"]))
            detail += section("Linked mitigations", *(labels(row.get("mitigations", []), mitigation_names) or ["No direct links"]))
            detail += section("Local control mappings", *(mapping["control_ids"] or ["Unmapped in this review"]))
            detail += section("Static rules", *(mapping["static_rule_ids"] or ["No static rule mapping"]))
            detail += section("Case references", ", ".join(mapping["case_ids"]) or "No direct references")
            rows["techniques"].append((values, detail))
        for key, row in atlas["mitigations"].items():
            values = (key, row["name"], str(len(row["techniques"])))
            detail = row["name"] + section("ATLAS mitigation", key)
            detail += section("Linked techniques", *labels(row["techniques"], technique_names))
            rows["mitigations"].append((values, detail))
        for key, name in atlas["tactics"].items():
            matches = [tid for tid, row in atlas["techniques"].items() if key in row["tactics"]]
            detail = name + section("ATLAS tactic", key)
            detail += section("Linked techniques", *labels(matches, technique_names))
            rows["tactics"].append(((key, name, str(len(matches))), detail))
        return rows

    def compose(self) -> ComposeResult:
        yield Header()
        summary = self.report["summary"]
        total = summary["catalog_techniques"]
        overview = (
            f"ATLAS {self.report['atlas_version']}   ·   {len(self.report['findings'])} static findings   ·   "
            f"{len(self.report['controls'])} controls   ·   {self.report['files_examined']} files examined\n"
            f"Technique mapping   {summary['techniques_mapped_to_controls']}/{total} to controls   ·   "
            f"{summary['techniques_mapped_to_static_rules']}/{total} to static rules"
        )
        yield Static(Text(overview, style="bold cyan"), id="overview")
        with TabbedContent():
            for key in COLUMNS:
                label = f"{key.title()} ({len(self.rows[key])})"
                with TabPane(label, id=key):
                    yield Input(placeholder="Filter by ID, status or text", id=f"search-{key}")
                    with Horizontal(classes="split"):
                        yield DataTable(id=f"table-{key}", classes="table", cursor_type="row", zebra_stripes=True)
                        with VerticalScroll(classes="detail-scroll"):
                            yield Static(id=f"detail-{key}", classes="detail")
            with TabPane("Review scope", id="scope"):
                with VerticalScroll():
                    report = self.report
                    text = f"Dataset: {report['atlas_source']}\n\n"
                    text += f"Files examined: {report['files_examined']}\nFiles skipped: {report['files_skipped']}\n"
                    text += "\nStatic findings: " + str(summary["findings"])
                    text += "\nControl outcomes: " + str(summary["controls"])
                    text += section("Evidence interpretation",
                                    "FAIL is a deterministic policy match. REVIEW calls for human verification.",
                                    "ATTESTED outcomes come from user-supplied evidence references.",
                                    "NOT_VERIFIED means evidence is missing. NOT_APPLICABLE is declared in the profile.")
                    text += section("Scan limitations", *(report["warnings"] or ["No scan warnings."]))
                    yield Static(Text(plain(text)))

        yield Footer()

    def on_mount(self):
        for key, columns in COLUMNS.items():
            self.query_one(f"#table-{key}", DataTable).add_columns(*columns)
            self.populate(key)

    def populate(self, key, query=""):
        table = self.query_one(f"#table-{key}", DataTable)
        table.clear()
        rows = [row for row in self.rows[key] if query.casefold() in (" ".join(row[0]) + "\n" + row[1]).casefold()]
        self.filtered_rows[key] = rows
        for values, _detail in rows:
            cells = [Text(plain(value)) for value in values]
            if key in {"findings", "controls"}:
                cells[1].stylize({"FAIL": "bold red", "REVIEW": "bold yellow",
                                  "ATTESTED_PASS": "green", "ATTESTED_FAIL": "red"}.get(values[1], ""))
            table.add_row(*cells)
        detail = rows[0][1] if rows else (
            "No static findings in the files examined. Review scan scope and control evidence."
            if key == "findings" and not query else "No records match this filter."
        )
        self.show_detail(key, detail)

    def show_detail(self, key, detail):
        target = self.query_one(f"#detail-{key}", Static)
        heading, separator, rest = plain(detail).partition("\n")
        text = Text(heading, style="bold cyan")
        text.append(separator + rest)
        target.update(text)
        target.parent.scroll_home(animate=False)

    def on_input_changed(self, event: Input.Changed):
        key = event.input.id.removeprefix("search-")
        self.populate(key, event.value.strip())

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted):
        key = event.data_table.id.removeprefix("table-")
        rows = self.filtered_rows.get(key, [])
        if 0 <= event.cursor_row < len(rows):
            self.show_detail(key, rows[event.cursor_row][1])
