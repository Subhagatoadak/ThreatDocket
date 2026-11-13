"""Terminal dashboard for local findings and MITRE ATLAS reference data."""
from pathlib import Path
import re
import time

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.suggester import SuggestFromList
from textual.widgets import (Button, Checkbox, DataTable, Footer, Header, Input, Markdown, ProgressBar, Select,
                             Static, TabbedContent, TabPane)

from . import advisory as llm
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
    BINDINGS = [
        ("q", "quit", "Quit"),
        Binding("ctrl+t", "llm('check')", "Check model", priority=True),
        Binding("ctrl+r", "llm('run')", "Run advisory", priority=True),
        Binding("ctrl+s", "llm('save')", "Save model settings", priority=True),
    ]
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
    #llm-form { width: 60; min-width: 36; padding: 0 1; }
    #llm-form Select, #llm-form Input { margin: 0 0 1 0; }
    #llm-form Input { background: $boost; height: 1; }
    .llm-label { color: $text-muted; height: 1; }
    .llm-hint { color: $text-muted; height: auto; margin: 0 0 1 0; }
    .llm-buttons { height: 3; margin: 1 0 0 0; }
    .llm-buttons Button { margin: 0 1 0 0; min-width: 10; }
    #llm-checks Checkbox { margin: 0 2 0 0; }
    #llm-checks { height: auto; }
    #llm-right { width: 1fr; padding: 0 1; border-left: solid $primary; }
    #llm-status { height: auto; }
    #llm-progress { margin: 0 0 1 0; }
    #llm-steps { height: auto; max-height: 14; }
    #llm-help { height: auto; }
    #ai-meta { height: auto; padding: 1 2; background: $panel; }
    #llm-result-scroll { height: 1fr; padding: 0 1; }
    """

    STATUS_ICONS = {"run": ("…", "yellow"), "ok": ("✓", "green"), "warn": ("!", "yellow"), "fail": ("✗", "bold red")}

    def __init__(self, report, config_file=None):
        super().__init__()
        self.report = report
        self.atlas = catalog()
        self.rows = self._rows()
        self.filtered_rows = {}
        self.config_file = config_file
        self.saved = llm.load_saved(config_file)
        try:
            self.llm_provider = llm.active_provider(self.saved)
        except ValueError:
            self.llm_provider = "openai"
        self.llm_drafts = {}
        self.llm_steps = []
        self.llm_started = None
        self.llm_waiting = ""
        self.ai_results = []

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
            with TabPane("AI advisor", id="advisor"):
                yield from self._compose_advisor()
            with TabPane("AI findings", id="ai-findings"):
                yield from self._compose_ai_findings()

        yield Footer()

    def _compose_advisor(self):
        current = llm.provider_settings(self.llm_provider, self.saved)
        spec = llm.PROVIDERS[self.llm_provider]
        with Horizontal(classes="split"):
            with VerticalScroll(id="llm-form"):
                yield Static("Provider", classes="llm-label")
                yield Select([(p.label, key) for key, p in llm.PROVIDERS.items()], value=self.llm_provider,
                             allow_blank=False, compact=True, id="llm-provider")
                yield Static("Model", classes="llm-label")
                yield Input(current.model, placeholder="Required: enter a model name", compact=True,
                            id="llm-model")
                yield Static("Base URL", classes="llm-label")
                yield Input(current.base_url, placeholder=spec.base_url or "https://your-endpoint.example/v1",
                            compact=True, id="llm-base-url")
                yield Static("API key", classes="llm-label")
                yield Input(current.api_key, placeholder="Paste your API key", password=True, compact=True,
                            id="llm-api-key")
                with Horizontal(id="llm-checks"):
                    yield Checkbox("Show key", compact=True, id="llm-show-key")
                    yield Checkbox("Remember key", value=True, compact=True, id="llm-remember")
                yield Static(self._hint(), id="llm-hint", classes="llm-hint")
                with Horizontal(classes="llm-buttons"):
                    yield Button("Check", id="llm-check", variant="primary")
                    yield Button("Run advisory", id="llm-run", variant="success")
                    yield Button("Save", id="llm-save")
            with Vertical(id="llm-right"):
                yield Static(Text("Ready. Press Check (Ctrl+T) to verify, then Run advisory (Ctrl+R).", style="dim"),
                             id="llm-status")
                yield ProgressBar(total=len(llm.CHECK_STEPS), show_eta=False, id="llm-progress")
                yield Static(id="llm-steps")
                yield Static(Text(
                    "\nHow it works\n"
                    "1. Choose a provider, paste an API key and enter a model name.\n"
                    "2. Change the base URL for a proxy, gateway or self-hosted endpoint.\n"
                    "3. Check (Ctrl+T) verifies everything; with no model entered it lists available models.\n"
                    "4. Run advisory (Ctrl+R). The answer opens in the AI findings tab.\n\n"
                    "Only aggregate rule counts and fixed remediation text are sent. Repository contents, "
                    "filenames, paths, evidence references and credential matches stay local.", style="dim"),
                    id="llm-help")

    def _compose_ai_findings(self):
        yield Static(Text("No AI findings yet.", style="bold"), id="ai-meta")
        with VerticalScroll(id="llm-result-scroll"):
            yield Markdown(
                "Open the **AI advisor** tab, configure a provider, API key and model, then press "
                "**Run advisory** (Ctrl+R). The model's analysis of your findings and control gaps appears here.",
                id="llm-result")

    def _hint(self):
        spec = llm.PROVIDERS[self.llm_provider]
        default = f"Default URL: {spec.base_url}" if spec.base_url else "Use the endpoint root, usually ending in /v1"
        location = str(self.config_file or llm.config_path()).replace(str(Path.home()), "~", 1)
        return f"{default}\nSettings file: {location} (owner-only)"

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
        if event.input.id and event.input.id.startswith("search-"):
            self.populate(event.input.id.removeprefix("search-"), event.value.strip())

    # ------------------------------------------------------------------ AI advisor

    def _form_config(self):
        return llm.LLMConfig(
            provider=self.llm_provider,
            model=self.query_one("#llm-model", Input).value.strip(),
            base_url=self.query_one("#llm-base-url", Input).value.strip(),
            api_key=self.query_one("#llm-api-key", Input).value.strip(),
        )

    def on_select_changed(self, event: Select.Changed):
        if event.select.id != "llm-provider" or event.value == self.llm_provider or event.value is Select.BLANK:
            return
        self.llm_drafts[self.llm_provider] = self._form_config()
        self.llm_provider = event.value
        config = self.llm_drafts.get(self.llm_provider) or llm.provider_settings(self.llm_provider, self.saved)
        spec = llm.PROVIDERS[self.llm_provider]
        model = self.query_one("#llm-model", Input)
        model.value, model.placeholder, model.suggester = config.model, "Required: enter a model name", None
        url = self.query_one("#llm-base-url", Input)
        url.value, url.placeholder = config.base_url, spec.base_url or "https://your-endpoint.example/v1"
        self.query_one("#llm-api-key", Input).value = config.api_key
        self.query_one("#llm-hint", Static).update(self._hint())
        self._reset_progress(len(llm.CHECK_STEPS), "")

    def on_checkbox_changed(self, event: Checkbox.Changed):
        if event.checkbox.id == "llm-show-key":
            self.query_one("#llm-api-key", Input).password = not event.value

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id in {"llm-save", "llm-check", "llm-run"}:
            self.action_llm(event.button.id.removeprefix("llm-"))

    def action_llm(self, action):
        self.query_one(TabbedContent).active = "advisor"
        if self.query_one("#llm-check", Button).disabled:  # a request is already running
            return
        if action == "save":
            self._save(self._form_config(), announce=True)
        elif action == "check":
            self._start(len(llm.CHECK_STEPS), "Checking connection…")
            self.run_check(self._form_config())
        elif action == "run":
            self._start(len(llm.ADVISE_STEPS), "Requesting advisory…")
            self.run_advice(self._form_config())

    def _save(self, config, announce=False):
        remember = self.query_one("#llm-remember", Checkbox).value
        try:
            path = llm.save_config(config, remember_key=remember, path=self.config_file)
        except (OSError, ValueError) as error:
            self._status(f"✗ Could not save settings: {plain(error)}", "bold red")
            return
        self.saved = llm.load_saved(self.config_file)
        if announce:
            self._status(f"✓ Saved {llm.PROVIDERS[config.provider].label} settings to {path}"
                         + ("" if remember else " (API key not stored)"), "green")

    def _status(self, message, style=""):
        self.query_one("#llm-status", Static).update(Text(plain(message), style=style))

    def _reset_progress(self, total, message):
        self.llm_steps = []
        self.query_one("#llm-progress", ProgressBar).update(total=total, progress=0)
        self.query_one("#llm-steps", Static).update("")
        self._status(message, "bold cyan")

    def _set_busy(self, busy):
        for name in ("llm-check", "llm-run", "llm-save", "llm-provider"):
            self.query_one("#" + name).disabled = busy

    def _start(self, total, message):
        self._reset_progress(total, message)
        self._set_busy(True)
        self.llm_started = time.monotonic()
        self.llm_waiting = ""
        self.ai_results = []
        self.llm_timer = self.set_interval(0.5, self._tick)

    def _tick(self):
        if self.llm_waiting and self.llm_started:
            self._status(f"{self.llm_waiting}  {time.monotonic() - self.llm_started:.0f}s", "bold cyan")

    def _finish(self, ok, message):
        if getattr(self, "llm_timer", None):
            self.llm_timer.stop()
        self.llm_waiting = ""
        self.ai_results = []
        self._set_busy(False)
        elapsed = f"  ({time.monotonic() - self.llm_started:.1f}s)" if self.llm_started else ""
        self._status(("✓ " if ok else "✗ ") + message + elapsed, "bold green" if ok else "bold red")

    def _progress(self, index, total, label, status, detail):
        """Called from the worker thread via call_from_thread."""
        if index < len(self.llm_steps):
            self.llm_steps[index] = (label, status, detail)
        else:
            self.llm_steps.append((label, status, detail))
        self.llm_waiting = f"{label}…" if status == "run" else ""
        done = sum(1 for _l, s, _d in self.llm_steps if s in {"ok", "warn"})
        self.query_one("#llm-progress", ProgressBar).update(total=total, progress=done)
        text = Text()
        for i, (name, state, info) in enumerate(self.llm_steps):
            icon, style = self.STATUS_ICONS[state]
            text.append(f" {icon} ", style=style)
            text.append(f"{i + 1}/{total} {name}\n", style="bold" if state == "run" else "")
            if info:
                text.append(f"     {plain(info)}\n", style="red" if state == "fail" else "dim")
        self.query_one("#llm-steps", Static).update(text)
        self._tick()

    def _apply_models(self, models):
        if models:
            self.query_one("#llm-model", Input).suggester = SuggestFromList(models, case_sensitive=False)

    @work(thread=True, exclusive=True, group="llm")
    def run_check(self, config):
        report = lambda *args: self.call_from_thread(self._progress, *args)
        ok, models = llm.check_connection(config, report)
        self.call_from_thread(self._apply_models, models)
        if ok:
            self.call_from_thread(self._save, config)
            warned = any(s == "warn" for _l, s, _d in self.llm_steps)
            self.call_from_thread(self._finish, True, "All checks passed" + (" with warnings" if warned else "")
                                  + " · settings saved · ready to run")
        else:
            self.call_from_thread(self._finish, False, "Check failed; fix the highlighted step and retry")

    @work(thread=True, exclusive=True, group="llm")
    def run_advice(self, config):
        report = lambda *args: self.call_from_thread(self._progress, *args)
        try:
            text = llm.advisory(self.report, config, report)
        except ValueError:
            self.call_from_thread(self._finish, False, "Advisory failed; see the failed step")
            return
        self.call_from_thread(self._save, config)
        self.call_from_thread(self._show_ai_findings, config, text)
        self.call_from_thread(self._finish, True, "Advisory received · opened in the AI findings tab")

    def _show_ai_findings(self, config, text):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        label = llm.PROVIDERS[config.provider].label
        self.ai_results.insert(0, (stamp, label, config.model, plain(text)))
        latest = self.ai_results[0]
        meta = Text(f"AI findings  ·  {latest[1]}  ·  {latest[2]}  ·  {latest[0]}", style="bold cyan")
        meta.append(f"\n{len(self.ai_results)} run(s) this session, newest first. Advisory text only; it does not "
                    "change findings, verdicts or CI.", style="dim")
        self.query_one("#ai-meta", Static).update(meta)
        body = "\n\n---\n\n".join(f"## {model} · {provider} · {when}\n\n{answer}"
                                     for when, provider, model, answer in self.ai_results)
        self.query_one("#llm-result", Markdown).update(body)
        tabs = self.query_one(TabbedContent)
        try:
            tabs.get_tab("ai-findings").label = f"AI findings ({len(self.ai_results)})"
        except Exception:  # label update is cosmetic
            pass
        tabs.active = "ai-findings"
        self.query_one("#llm-result-scroll", VerticalScroll).scroll_home(animate=False)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted):
        key = event.data_table.id.removeprefix("table-")
        rows = self.filtered_rows.get(key, [])
        if 0 <= event.cursor_row < len(rows):
            self.show_detail(key, rows[event.cursor_row][1])
