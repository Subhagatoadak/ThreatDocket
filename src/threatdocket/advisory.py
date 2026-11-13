"""Optional explanation of fixed, redacted findings using a compatible endpoint."""
from collections import Counter
import json
import os
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .static import RULES

MAX_RESPONSE = 512 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def advisory(report):
    model = os.getenv("ATLAS_LLM_MODEL", "").strip()
    url = os.getenv("ATLAS_LLM_BASE_URL", "").rstrip("/")
    key = os.getenv("ATLAS_LLM_API_KEY", "").strip()
    if not url or not model:
        raise ValueError("Set ATLAS_LLM_BASE_URL and ATLAS_LLM_MODEL before requesting advice")
    parsed = urlsplit(url)
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if not parsed.hostname or not (parsed.scheme == "https" or (local and parsed.scheme == "http")) or (
        parsed.username or parsed.password or parsed.query or parsed.fragment
    ):
        raise ValueError("Use an HTTPS model base URL or an HTTP loopback endpoint")

    counts = Counter(item["rule"] for item in report["findings"] if item["rule"] in RULES)
    shared = {
        "atlas_version": report["atlas_version"],
        "rule_counts": [
            {"id": rule, "title": RULES[rule][2], "count": count, "defensive_action": RULES[rule][4]}
            for rule, count in sorted(counts.items())
        ],
        "control_outcome_counts": report["summary"]["controls"],
    }
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Explain defensive priorities and evidence gaps from these aggregate local review results. Use only the data provided. Avoid claiming exploitability or generating reproduction instructions."},
            {"role": "user", "content": json.dumps(shared)},
        ],
    }
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    request = Request(url + "/chat/completions", data=json.dumps(body).encode(), headers=headers)
    try:
        with build_opener(NoRedirect()).open(request, timeout=20) as response:
            data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE:
            raise ValueError("Response exceeds the size limit")
        content = json.loads(data)["choices"][0]["message"]["content"]
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Empty advisory")
        return content
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        raise ValueError("The configured model did not return a usable advisory") from error
