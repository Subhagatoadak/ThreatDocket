"""Optional explanation of fixed, redacted findings using a configurable model provider.

Supported providers: OpenAI (GPT), Anthropic (Claude), Google (Gemini), and any
OpenAI-compatible endpoint. Every provider accepts a base URL override so the
same API key can be used through a proxy, gateway, or regional endpoint.
"""
from collections import Counter
from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
import re
import socket
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .static import RULES

MAX_RESPONSE = 512 * 1024
LIST_TIMEOUT = 15
GENERATE_TIMEOUT = 120
ANTHROPIC_VERSION = "2023-06-01"
MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}")
SYSTEM_PROMPT = (
    "Explain defensive priorities and evidence gaps from these aggregate local review results. "
    "Use only the data provided. Avoid claiming exploitability or generating reproduction instructions."
)


@dataclass(frozen=True)
class Provider:
    id: str
    label: str
    base_url: str
    key_env: tuple = ()
    key_required: bool = True


PROVIDERS = {
    "openai": Provider("openai", "OpenAI (GPT)", "https://api.openai.com/v1", ("OPENAI_API_KEY",)),
    "anthropic": Provider("anthropic", "Anthropic (Claude)", "https://api.anthropic.com/v1",
                          ("ANTHROPIC_API_KEY",)),
    "gemini": Provider("gemini", "Google (Gemini)", "https://generativelanguage.googleapis.com/v1beta",
                       ("GEMINI_API_KEY", "GOOGLE_API_KEY")),
    "compatible": Provider("compatible", "OpenAI-compatible (custom URL)", "", (), key_required=False),
}


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    model: str
    base_url: str
    api_key: str = ""

    def __repr__(self):  # never print the key
        return (f"LLMConfig(provider={self.provider!r}, model={self.model!r}, "
                f"base_url={self.base_url!r}, api_key={'***' if self.api_key else ''!r})")


class ProviderError(ValueError):
    """A provider request failed; the message is safe to show to the user."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# --------------------------------------------------------------------------- config persistence

def config_path():
    """Location of the saved settings file (owner-only permissions)."""
    if os.getenv("ATLAS_CONFIG_DIR"):
        base = Path(os.environ["ATLAS_CONFIG_DIR"])
    else:
        base = Path(os.getenv("XDG_CONFIG_HOME") or Path.home() / ".config") / "threatdocket"
    return base / "config.json"


def load_saved(path=None):
    path = Path(path) if path else config_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"provider": "", "providers": {}}
    if not isinstance(data, dict):
        return {"provider": "", "providers": {}}
    providers = data.get("providers") if isinstance(data.get("providers"), dict) else {}
    clean = {}
    for key, value in providers.items():
        if key in PROVIDERS and isinstance(value, dict):
            clean[key] = {k: v for k, v in value.items() if k in {"model", "base_url", "api_key"} and isinstance(v, str)}
    provider = data.get("provider") if data.get("provider") in PROVIDERS else ""
    return {"provider": provider, "providers": clean}


def save_config(config, remember_key=True, path=None):
    """Persist settings for one provider and make it the active provider."""
    if config.provider not in PROVIDERS:
        raise ValueError("Unknown provider")
    path = Path(path) if path else config_path()
    data = load_saved(path)
    entry = {"model": config.model, "base_url": config.base_url}
    if remember_key and config.api_key:
        entry["api_key"] = config.api_key
    data["provider"] = config.provider
    data["providers"][config.provider] = entry
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=".config-", dir=path.parent)
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def provider_settings(provider, saved=None):
    """Settings to show for a provider: environment overrides, then saved values, then defaults."""
    spec = PROVIDERS[provider]
    saved = saved or load_saved()
    try:
        is_active = provider == active_provider(saved)
    except ValueError:
        is_active = False
    stored = saved["providers"].get(provider, {})

    def env(name):  # generic ATLAS_LLM_* overrides target only the active provider
        return os.getenv(name, "").strip() if is_active else ""

    env_key = next((os.environ[name].strip() for name in spec.key_env if os.getenv(name, "").strip()), "")
    return LLMConfig(
        provider=provider,
        model=env("ATLAS_LLM_MODEL") or stored.get("model") or "",  # no default: the user chooses
        base_url=env("ATLAS_LLM_BASE_URL") or stored.get("base_url") or spec.base_url,
        api_key=env("ATLAS_LLM_API_KEY") or stored.get("api_key") or env_key,
    )


def active_provider(saved=None):
    saved = saved or load_saved()
    env = os.getenv("ATLAS_LLM_PROVIDER", "").strip().lower()
    if env:
        if env not in PROVIDERS:
            raise ValueError("ATLAS_LLM_PROVIDER must be one of: " + ", ".join(PROVIDERS))
        return env
    if saved["provider"]:
        return saved["provider"]
    # Backward compatibility: a bare base URL meant an OpenAI-compatible endpoint.
    return "compatible" if os.getenv("ATLAS_LLM_BASE_URL", "").strip() else "openai"


def resolve_config(provider=None, model=None, base_url=None, api_key=None, path=None):
    saved = load_saved(path)
    provider = (provider or active_provider(saved)).strip().lower()
    if provider not in PROVIDERS:
        raise ValueError("Provider must be one of: " + ", ".join(PROVIDERS))
    config = provider_settings(provider, saved)
    return replace(config, model=model or config.model, base_url=base_url or config.base_url,
                   api_key=api_key or config.api_key)


# --------------------------------------------------------------------------- validation

def validate(config, require_model=True):
    """Return a normalized config or raise ValueError with a user-facing message."""
    if config.provider not in PROVIDERS:
        raise ValueError("Choose a provider: " + ", ".join(PROVIDERS))
    spec = PROVIDERS[config.provider]
    url = (config.base_url or spec.base_url).strip().rstrip("/")
    if not url:
        raise ValueError("Enter a base URL for the endpoint (usually ending in /v1)")
    parsed = urlsplit(url)
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if not parsed.hostname or not (parsed.scheme == "https" or (local and parsed.scheme == "http")):
        raise ValueError("Base URL must use HTTPS (plain HTTP is accepted only for localhost)")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Base URL must not contain credentials, a query string, or a fragment")
    model = (config.model or "").strip()
    if config.provider == "gemini":
        model = model.removeprefix("models/")
    if not model and require_model:
        raise ValueError("Enter a model name (press Check or run check-llm to list the models your key can use)")
    if model and not MODEL_NAME.fullmatch(model):
        raise ValueError("Model name contains unsupported characters")
    key = (config.api_key or "").strip()
    if spec.key_required and not key:
        raise ValueError(f"Enter an API key for {spec.label}")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) > 126 for ch in key):
        raise ValueError("API key contains whitespace or non-printable characters")
    return LLMConfig(config.provider, model, url, key)


# --------------------------------------------------------------------------- HTTP

def _headers(config):
    headers = {"Content-Type": "application/json", "Accept": "application/json",
               "User-Agent": "threatdocket"}
    if config.provider == "anthropic":
        headers["anthropic-version"] = ANTHROPIC_VERSION
        if config.api_key:
            headers["x-api-key"] = config.api_key
    elif config.provider == "gemini":
        if config.api_key:
            headers["x-goog-api-key"] = config.api_key
    elif config.api_key:
        headers["Authorization"] = "Bearer " + config.api_key
    return headers


def _redact(text, config):
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]", "", str(text))
    if config.api_key and len(config.api_key) >= 4:
        text = text.replace(config.api_key, "***")
    return text[:400]


HINTS = {
    400: "the request was rejected; check the model name",
    401: "authentication failed; check the API key",
    403: "access denied; check the API key and that it can use this model",
    404: "not found; check the base URL and model name",
    429: "rate limit or quota exceeded; check plan/billing or retry later",
}


def _request(config, method, url, body=None, timeout=GENERATE_TIMEOUT):
    data = json.dumps(body).encode() if body is not None else None
    request = Request(url, data=data, headers=_headers(config), method=method)
    try:
        with build_opener(NoRedirect()).open(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE + 1)
    except HTTPError as error:
        detail = ""
        try:
            with error:
                payload = json.loads(error.read(MAX_RESPONSE))
            err = payload.get("error", payload) if isinstance(payload, dict) else payload
            if isinstance(err, list) and err:  # some gateways wrap errors in a list
                err = err[0].get("error", err[0]) if isinstance(err[0], dict) else err[0]
            detail = str(err.get("message", "")) if isinstance(err, dict) else str(err)
        except (OSError, ValueError, AttributeError):
            pass
        code = error.code
        if code == 400 and "api key" in detail.lower():  # Gemini reports bad keys as 400
            code_hint = HINTS[401]
        else:
            code_hint = None
        hint = code_hint or HINTS.get(code) or ("redirects are not followed; use the final URL" if 300 <= code < 400
                                   else "the provider reported a server error" if code >= 500 else "request failed")
        message = f"HTTP {code}: {hint}"
        if detail:
            message += f" ({_redact(detail, config)})"
        raise ProviderError(message, code) from None
    except TimeoutError:
        raise ProviderError(f"No response within {timeout} seconds") from None
    except URLError as error:
        raise ProviderError("Could not connect: " + _redact(getattr(error, "reason", error), config)) from None
    except OSError as error:
        raise ProviderError("Connection error: " + _redact(error, config)) from None
    if len(raw) > MAX_RESPONSE:
        raise ProviderError("Response exceeds the size limit")
    try:
        return json.loads(raw)
    except ValueError:
        raise ProviderError("The endpoint did not return JSON; check the base URL") from None


# --------------------------------------------------------------------------- provider operations

def list_models(config):
    """Return the model IDs the key can see (best effort; some compatible servers lack this)."""
    config = validate(config, require_model=False)
    models = []
    if config.provider == "gemini":
        token = ""
        for _ in range(10):
            url = config.base_url + "/models?pageSize=1000" + ("&pageToken=" + quote(token, safe="") if token else "")
            data = _request(config, "GET", url, timeout=LIST_TIMEOUT)
            for item in data.get("models", []) if isinstance(data, dict) else []:
                methods = item.get("supportedGenerationMethods") or ["generateContent"]
                if isinstance(item.get("name"), str) and "generateContent" in methods:
                    models.append(item["name"].removeprefix("models/"))
            token = data.get("nextPageToken") if isinstance(data, dict) else ""
            if not token:
                break
    else:
        url = config.base_url + "/models" + ("?limit=1000" if config.provider == "anthropic" else "")
        data = _request(config, "GET", url, timeout=LIST_TIMEOUT)
        items = data.get("data", data.get("models", [])) if isinstance(data, dict) else []
        for item in items if isinstance(items, list) else []:
            name = item.get("id") or item.get("name") if isinstance(item, dict) else item
            if isinstance(name, str):
                models.append(name)
    return sorted(set(models))


def generate(config, system, user, max_tokens=4096, timeout=GENERATE_TIMEOUT):
    config = validate(config)
    if config.provider == "anthropic":
        body = {"model": config.model, "max_tokens": max_tokens, "system": system,
                "messages": [{"role": "user", "content": user}]}
        data = _request(config, "POST", config.base_url + "/messages", body, timeout)
        blocks = data.get("content") if isinstance(data, dict) else None
        text = "".join(b.get("text", "") for b in blocks or [] if isinstance(b, dict) and b.get("type") == "text")
    elif config.provider == "gemini":
        body = {"systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}]}
        url = f"{config.base_url}/models/{quote(config.model, safe='-._')}:generateContent"
        data = _request(config, "POST", url, body, timeout)
        candidates = data.get("candidates") if isinstance(data, dict) else None
        if not candidates:
            reason = (data.get("promptFeedback") or {}).get("blockReason") if isinstance(data, dict) else None
            raise ProviderError("The model returned no candidates" + (f" (blocked: {reason})" if reason else ""))
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict) and not p.get("thought"))
    else:
        body = {"model": config.model, "messages": [{"role": "system", "content": system},
                                                    {"role": "user", "content": user}]}
        data = _request(config, "POST", config.base_url + "/chat/completions", body, timeout)
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ProviderError("Unexpected response shape; is this an OpenAI-compatible endpoint?") from None
    if not isinstance(text, str) or not text.strip():
        raise ProviderError("The model returned an empty response")
    return text


# --------------------------------------------------------------------------- checks and advice

CHECK_STEPS = (
    "Validate settings",
    "Resolve host",
    "Authenticate and list models",
    "Confirm model is available",
    "Test generation",
)


def check_connection(config, progress=lambda *a: None):
    """Run every check in order, reporting progress(index, total, label, status, detail).

    status is "run", "ok", "warn", or "fail". Returns (ok, models).
    """
    total = len(CHECK_STEPS)
    models = []

    def step(i, func):
        progress(i, total, CHECK_STEPS[i], "run", "")
        try:
            status, detail = func()
        except (ProviderError, ValueError) as error:
            progress(i, total, CHECK_STEPS[i], "fail", str(error))
            return False
        progress(i, total, CHECK_STEPS[i], status, detail)
        return True

    state = {}

    def settings():
        state["config"] = validate(config, require_model=False)
        c = state["config"]
        return "ok", f"{PROVIDERS[c.provider].label} · {c.model or 'no model entered yet'} · {c.base_url}"

    def resolve():
        host = urlsplit(state["config"].base_url).hostname
        try:
            addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
        except OSError as error:
            raise ProviderError(f"Cannot resolve {host}: {error}") from None
        return "ok", f"{host} → {', '.join(sorted(addresses)[:3])}"

    def auth():
        try:
            models.extend(list_models(state["config"]))
        except ProviderError as error:
            if state["config"].provider == "compatible" and error.status in {404, 405, 501}:
                return "warn", "Endpoint has no model listing; continuing"
            raise
        return "ok", f"Key accepted · {len(models)} models visible"

    def model():
        name = state["config"].model
        if not name:
            listing = ", ".join(models[:12]) + (f" … (+{len(models) - 12} more)" if len(models) > 12 else "")
            raise ProviderError("Enter a model name" + (f". Your key can use: {listing}" if models else ""))
        if not models:
            return "warn", "Could not verify the model from a listing; the test call will confirm it"
        if name in models:
            return "ok", f"{name} is available"
        close = [m for m in models if name.split("-")[0] in m][:5]
        return "warn", f"{name} is not in the listing" + (f"; similar: {', '.join(close)}" if close else "")

    def test():
        text = generate(state["config"], "You are a connectivity check.", "Reply with the single word OK.",
                        max_tokens=64, timeout=60)
        return "ok", "Model replied: " + _redact(text.strip().splitlines()[0], state["config"])[:60]

    for i, func in enumerate((settings, resolve, auth, model, test)):
        if not step(i, func):
            return False, models
    return True, models


def redacted_summary(report):
    counts = Counter(item["rule"] for item in report["findings"] if item["rule"] in RULES)
    return {
        "atlas_version": report["atlas_version"],
        "rule_counts": [
            {"id": rule, "title": RULES[rule][2], "count": count, "defensive_action": RULES[rule][4]}
            for rule, count in sorted(counts.items())
        ],
        "control_outcome_counts": report["summary"]["controls"],
    }


ADVISE_STEPS = ("Validate settings", "Prepare redacted summary", "Waiting for model response", "Validate response")


def advisory(report, config=None, progress=lambda *a: None):
    """Return advisory text. Only aggregate, fixed rule data leaves the machine."""
    total = len(ADVISE_STEPS)
    progress(0, total, ADVISE_STEPS[0], "run", "")
    try:
        config = validate(config or resolve_config())
    except ValueError as error:
        progress(0, total, ADVISE_STEPS[0], "fail", str(error))
        raise
    progress(0, total, ADVISE_STEPS[0], "ok", f"{PROVIDERS[config.provider].label} · {config.model}")
    progress(1, total, ADVISE_STEPS[1], "run", "")
    shared = json.dumps(redacted_summary(report))
    progress(1, total, ADVISE_STEPS[1], "ok", f"{len(shared)} bytes of aggregate counts; no file contents")
    progress(2, total, ADVISE_STEPS[2], "run", "")
    try:
        text = generate(config, SYSTEM_PROMPT, shared)
    except ProviderError as error:
        progress(2, total, ADVISE_STEPS[2], "fail", str(error))
        raise ValueError("The configured model did not return a usable advisory: " + str(error)) from None
    progress(2, total, ADVISE_STEPS[2], "ok", "")
    progress(3, total, ADVISE_STEPS[3], "ok", f"{len(text)} characters")
    return text
