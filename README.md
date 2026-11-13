# ThreatDocket

A standalone Python tool for reviewing AI security controls in a local project. The terminal dashboard combines static findings, evidence-backed control review, and a versioned MITRE ATLAS reference catalog.

## Install and open the dashboard

Requires Python 3.11 or later and a terminal. Clone the repository and install the package:

```bash
git clone https://github.com/Subhagatoadak/ThreatDocket.git
cd ThreatDocket
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
threatdocket tui /path/to/your/project
```

On Windows PowerShell use `py -3 -m venv .venv` and `.venv\Scripts\Activate.ps1`. Installing dependencies may require package-index access. The dashboard and local analysis work offline after installation.

Try the included example. Its policy and evidence are illustrative.

```bash
threatdocket tui examples/demo --profile examples/profile.json --evidence examples/evidence.json --policy examples/policy.json
```

Use Tab or mouse clicks to move through the dashboard. Use arrow keys in a table to inspect rows. Type a case ID, technique ID, control status, or text into the tab’s filter. The Review scope tab shows file counts, scan warnings, and verdict definitions.

## What the package checks

| Check | Inputs |
| --- | --- |
| Credential-like values and private-key markers | Supported local source and configuration files |
| Shell-enabled subprocess calls and dynamic evaluation | Python syntax trees |
| Privileged containers, host-network use, and host-path mounts | Supported Kubernetes workload manifests |
| Broad workflow token permissions and privileged pull-request triggers | GitHub Actions workflow YAML |
| Explicit root user in the final Docker stage | Dockerfiles |

These are nine focused rules. Each finding includes a location, defensive action, and an ATLAS reference. The dashboard also includes all **77 cases, 221 techniques and sub-techniques, 16 tactics, and 44 mitigations** from the pinned v2026.10 release. Technique rows show local control mappings, including unmapped entries.

The filesystem scanner visits recognized text formats under the supplied directory and excludes common vendor/build folders and symlinks. It does not apply .gitignore, evaluate templated manifests, resolve inherited Docker image users, or infer effective permissions in a deployment. It reads at most 5,000 candidate files, up to 512 KiB each, and returns at most 3,000 findings. Check skipped-file counts and warnings before interpreting results. Findings are local indicators and configuration policy matches. Establish runtime behavior through independently collected evidence.

## Plug in your architecture and controls

- **Profile** declares whether each supported feature exists. Omitted features have unknown applicability. See `examples/profile.json` for all feature names.
- **Evidence** records a control outcome and an opaque reference to the actual evidence. The tool does not read or verify the referenced material. See `examples/evidence.json`.
- **Policy** adds declarative controls by ID, architecture feature, ATLAS technique IDs, and required evidence. Built-ins remain available. See `examples/policy.json`.

Static findings use `FAIL` for explicit configuration policy matches and `REVIEW` for patterns that need human verification. Control rows use `ATTESTED_PASS` or `ATTESTED_FAIL` for supplied outcomes, `NOT_VERIFIED` for missing evidence, and `NOT_APPLICABLE` for explicitly absent features. Conflicting evidence and profile declarations yield `REVIEW`. An empty findings table means no enabled static rule matched the files examined.

## CI and Python integration

```bash
threatdocket scan . --profile examples/profile.json --output report.json --fail-on-findings
```

Exit codes are `0` for successful execution, `1` when the opt-in CI gate sees a static `FAIL` or an `ATTESTED_FAIL`, and `2` for invalid arguments or input errors. An existing output file is protected from overwrite.

```python
from threatdocket import catalog, review

report = review("/path/to/project", profile="profile.json", evidence="evidence.json")
print(report["summary"])
reference = catalog()
```

## Optional model advice

Only an explicit request calls a model. Supported providers are **OpenAI (GPT)**, **Anthropic (Claude)**, **Google (Gemini)** and any **OpenAI-compatible** endpoint (Ollama, vLLM, LM Studio, LiteLLM, Azure/OpenRouter-style gateways).

### Configure in the dashboard

Open the **AI advisor** tab in `threatdocket tui`:

1. Pick a provider. The base URL is prefilled with that provider's default.
2. Paste your API key, then enter a **model name** (required; there is no default model). Change the **Base URL** to route the same key through a proxy, gateway, regional or self-hosted endpoint. If you don't know the model name, leave it empty and press **Check**: it verifies the key and lists the models your key can use.
3. Press **Check** (`Ctrl+T`). A progress bar runs five checks: settings validation, DNS resolution, authentication and model listing, model availability, and a one-word test generation. A failed step shows the provider's reason with any key redacted. After the check passes, the model field suggests the model IDs your key can see.
4. Press **Run advisory** (`Ctrl+R`). The answer opens in the **AI findings** tab; repeated runs in a session stack there, newest first.

Successful checks and runs save the settings for each provider to `~/.config/threatdocket/config.json`, with owner-only permissions. Untick **Remember key** to keep the key out of that file. **Save** (`Ctrl+S`) stores the settings without running anything. `THREATDOCKET_CONFIG_DIR` relocates the file.

### Configure from the command line

```bash
export ANTHROPIC_API_KEY=...            # or OPENAI_API_KEY, GEMINI_API_KEY / GOOGLE_API_KEY
threatdocket check-llm --provider anthropic                      # lists models if --model is omitted
threatdocket check-llm --provider anthropic --model claude-sonnet-5-5
threatdocket advise /path/to/project --provider anthropic --model claude-sonnet-5-5
threatdocket advise /path/to/project --provider openai --base-url https://gateway.example/v1
```

The precedence is command-line flags, then `THREATDOCKET_LLM_PROVIDER` / `THREATDOCKET_LLM_MODEL` / `THREATDOCKET_LLM_BASE_URL` / `THREATDOCKET_LLM_API_KEY` (applied to the active provider), then saved settings, then the provider's standard key variable and default base URL. A model name must always be supplied (`--model`, `THREATDOCKET_LLM_MODEL`, or saved settings). The earlier `ATLAS_LLM_*` names are still accepted, and setting only a base URL and model, as in earlier versions, still selects an OpenAI-compatible endpoint. `check-llm` exits `0` when every check passes and `1` otherwise.

Base URLs must use HTTPS. Plain HTTP is accepted only for localhost. Redirects are not followed. The request contains fixed rule labels, remediation text, and counts. Repository contents, filenames, paths, evidence references, and credential matches stay local. Advice is advisory text and has no effect on findings, verdicts, or CI.

## ATLAS provenance

The package bundles normalized ATLAS names, IDs, dates, and relationships from the [MITRE ATLAS v2026.10 release](https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.10). The source asset SHA-256 is `ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d`. The original attribution and license are included. Case summaries, proposed checks, and local control mappings were authored for this package. This tool is an independent project.
