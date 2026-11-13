"""Assess a local repository against a pinned ATLAS catalog."""
from collections import Counter, defaultdict
from dataclasses import asdict
from functools import lru_cache
from importlib.resources import files
import json
from pathlib import Path
import re

from .controls import CONTROLS, Control
from .static import RULES, read_regular, scan

MAX_INPUT = 2 * 1024 * 1024
FEATURES = frozenset(control.feature for control in CONTROLS)
IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{0,62}")


@lru_cache(maxsize=1)
def _catalog():
    return json.loads(files("threatdocket").joinpath("data", "atlas.json").read_text(encoding="utf-8"))


def catalog():
    """Return the pinned, normalized reference catalog."""
    import copy

    return copy.deepcopy(_catalog())


def load_object(path):
    path = Path(path)
    try:
        value = json.loads(read_regular(path, MAX_INPUT).decode("utf-8"))
    except (OSError, ValueError, RecursionError) as error:
        raise ValueError(f"Could not read {path.name} as a bounded JSON file") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def _profile(path):
    if path is None:
        return {}
    profile = load_object(path)
    features = profile.get("features", {})
    if not isinstance(features, dict) or any(k not in FEATURES or type(v) is not bool
                                             for k, v in features.items()):
        raise ValueError("Profile features must use known feature names and true or false")
    return features


def _controls(path):
    if path is None:
        return CONTROLS
    rows = load_object(path).get("controls")
    if not isinstance(rows, list) or len(rows) > 100:
        raise ValueError("Policy must contain a controls list with at most 100 entries")
    controls = list(CONTROLS)
    known = {c.id for c in controls}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Each policy control must be an object")
        key, title, feature, technique_ids, evidence = (
            row.get(k) for k in ("id", "title", "feature", "techniques", "evidence")
        )
        if not isinstance(key, str) or not IDENTIFIER.fullmatch(key) or key in known:
            raise ValueError("Policy control IDs must be unique lowercase identifiers")
        if not isinstance(feature, str) or feature not in FEATURES:
            raise ValueError(f"Unknown policy feature for {key}")
        if not isinstance(technique_ids, list) or not technique_ids or any(
            not isinstance(t, str) or t not in _catalog()["techniques"] for t in technique_ids
        ):
            raise ValueError(f"Invalid ATLAS techniques for {key}")
        if any(not isinstance(s, str) or not s.strip() or len(s) > 400 for s in (title, evidence)):
            raise ValueError(f"Invalid title or evidence requirement for {key}")
        known.add(key)
        controls.append(Control(key, title, feature, tuple(dict.fromkeys(technique_ids)), evidence))
    return controls


def _evidence(path, controls):
    if path is None:
        return {}
    rows = load_object(path).get("controls")
    if not isinstance(rows, dict) or set(rows) - {control.id for control in controls}:
        raise ValueError("Evidence must provide an object keyed by known control ID")
    for key, value in rows.items():
        if not isinstance(value, dict) or value.get("outcome") not in ("pass", "fail"):
            raise ValueError(f"Evidence for {key} requires outcome pass or fail")
        reference = value.get("reference")
        if not isinstance(reference, str) or not reference.strip() or len(reference) > 240:
            raise ValueError(f"Evidence for {key} requires a short reference")
    return rows


def review(root, *, profile=None, evidence=None, policy=None):
    """Return a JSON-serializable local assessment.

    Optional profile, evidence and policy arguments are paths to JSON files.
    Supplied control outcomes are attestations with opaque evidence references.
    """
    project = Path(root).expanduser().resolve(strict=True)
    if not project.is_dir():
        raise ValueError("Project path must be a directory")
    features = _profile(profile)
    controls = _controls(policy)
    evidence_rows = _evidence(evidence, controls)
    source = _catalog()
    findings, warnings, examined, skipped = scan(project)
    case_index = defaultdict(list)
    for case in source["cases"]:
        for tid in case["techniques"]:
            case_index[tid].append(case["id"])

    for item in findings:
        item["cases"] = case_index[item["technique"]]

    rows = []
    for control in controls:
        item = asdict(control)
        evidence_row = evidence_rows.get(control.id)
        feature = features.get(control.feature)
        item["cases"] = sorted({cid for tid in control.techniques for cid in case_index[tid]})
        item["status"] = "NOT_APPLICABLE" if feature is False else (
            "NOT_VERIFIED" if not evidence_row else "ATTESTED_" + evidence_row["outcome"].upper()
        )
        item["applicability"] = "absent" if feature is False else "present" if feature is True else "unknown"
        item["reference"] = evidence_row["reference"] if evidence_row else None
        if feature is False and evidence_row:
            item["status"] = "REVIEW"
            warnings.append(f"{control.id}: supplied evidence conflicts with the feature marked absent.")
        rows.append(item)

    active = {tid for control in rows if control["applicability"] == "present"
              for tid in control["techniques"]}
    mapped = {tid for control in rows for tid in control["techniques"]}
    observed = {item["technique"] for item in findings}
    controls_by_technique = defaultdict(list)
    for item in rows:
        for technique in item["techniques"]:
            controls_by_technique[technique].append(item["id"])
    rules_by_technique = defaultdict(list)
    for rule, definition in RULES.items():
        rules_by_technique[definition[3]].append(rule)
    static_rule_mapped = {row[3] for row in RULES.values()}
    return {
        "schema_version": 1,
        "atlas_version": source["version"],
        "atlas_source": source["source"],
        "files_examined": examined,
        "files_skipped": skipped,
        "warnings": warnings,
        "findings": findings,
        "controls": rows,
        "technique_coverage": {
            technique: {
                "control_ids": controls_by_technique[technique],
                "static_rule_ids": rules_by_technique[technique],
                "case_ids": case_index[technique],
                "feature_present": technique in active,
                "finding_observed": technique in observed,
            }
            for technique in source["techniques"]
        },
        "summary": {
            "findings": dict(Counter(item["status"] for item in findings)),
            "controls": dict(Counter(item["status"] for item in rows)),
            "catalog_cases": len(source["cases"]),
            "catalog_techniques": len(source["techniques"]),
            "techniques_mapped_to_controls": len(mapped),
            "techniques_with_present_feature": len(active),
            "techniques_mapped_to_static_rules": len(static_rule_mapped),
            "techniques_referenced_by_findings": len(observed),
        },
    }
