import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from threatdocket import advisory as llm
from threatdocket.cli import main
from threatdocket.review import review

from mock_providers import KEY, Handler, start

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
CLEAN_ENV = {k: v for k, v in os.environ.items()
             if not k.startswith(("ATLAS_", "THREATDOCKET_")) and k not in {"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"}}


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.url = start()
        cls.report = review(EXAMPLES / "demo", profile=EXAMPLES / "profile.json")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        env = dict(CLEAN_ENV, THREATDOCKET_CONFIG_DIR=self.tmp.name)
        self.env = mock.patch.dict(os.environ, env, clear=True)
        self.env.start()
        Handler.log.clear()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def cfg(self, provider, model, key=KEY, path=None):
        base = {"openai": "/openai/v1", "anthropic": "/anthropic/v1", "gemini": "/gemini/v1beta",
                "compatible": "/compat/v1"}[provider]
        return llm.LLMConfig(provider, model, self.url + (path or base), key)


class ProviderTests(Base):
    def test_each_provider_generates_and_lists(self):
        for provider, model, expected, models in (
            ("openai", "gpt-5", "OK from GPT", ["gpt-5", "gpt-5-mini"]),
            ("anthropic", "claude-sonnet-5-5", "OK from Claude", ["claude-opus-5-5", "claude-sonnet-5-5"]),
            ("gemini", "models/gemini-2.5-flash", "OK from Gemini", ["gemini-2.5-flash", "gemini-2.5-pro"]),
        ):
            with self.subTest(provider):
                config = self.cfg(provider, model)
                self.assertEqual(llm.generate(config, "s", "u"), expected)
                self.assertEqual(llm.list_models(config), models)

    def test_compatible_without_key(self):
        self.assertEqual(llm.generate(self.cfg("compatible", "llama", key=""), "s", "u"), "OK from compatible")
        self.assertNotIn("Authorization", Handler.log[-1]["headers"])

    def test_auth_headers_are_provider_specific(self):
        llm.generate(self.cfg("gemini", "gemini-2.5-flash"), "s", "u")
        headers = {k.lower(): v for k, v in Handler.log[-1]["headers"].items()}
        self.assertEqual(headers["x-goog-api-key"], KEY)
        self.assertNotIn("authorization", headers)
        self.assertNotIn(KEY, Handler.log[-1]["path"])  # key never in URL

    def test_bad_key_is_redacted_and_explained(self):
        bad = "sk-WRONG-abcdef"
        with self.assertRaises(llm.ProviderError) as ctx:
            llm.generate(self.cfg("openai", "gpt-5", key=bad), "s", "u")
        self.assertEqual(ctx.exception.status, 401)
        self.assertIn("check the API key", str(ctx.exception))
        self.assertNotIn(bad, str(ctx.exception))
        with self.assertRaises(llm.ProviderError) as ctx:
            llm.list_models(self.cfg("gemini", "gemini-2.5-flash", key=bad))
        self.assertIn("HTTP 403", str(ctx.exception))

    def test_gemini_style_400_bad_key_hint(self):
        error = llm.HTTPError("u", 400, "Bad", {}, __import__("io").BytesIO(
            b'{"error": {"code": 400, "message": "API key not valid. Please pass a valid API key."}}'))
        with mock.patch.object(llm, "build_opener") as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaisesRegex(llm.ProviderError, "check the API key"):
                llm.list_models(self.cfg("gemini", "gemini-2.5-flash"))

    def test_unknown_model_404(self):
        with self.assertRaises(llm.ProviderError) as ctx:
            llm.generate(self.cfg("openai", "gpt-nope"), "s", "u")
        self.assertIn("HTTP 404", str(ctx.exception))
        self.assertIn("gpt-nope does not exist", str(ctx.exception))

    def test_redirects_not_followed_and_non_json(self):
        with self.assertRaises(llm.ProviderError) as ctx:
            llm.generate(self.cfg("openai", "gpt-5", path="/redirect/v1"), "s", "u")
        self.assertIn("redirects are not followed", str(ctx.exception))
        with self.assertRaises(llm.ProviderError) as ctx:
            llm.generate(self.cfg("openai", "gpt-5", path="/html/v1"), "s", "u")
        self.assertIn("did not return JSON", str(ctx.exception))

    def test_connection_refused(self):
        config = llm.LLMConfig("openai", "gpt-5", "http://127.0.0.1:1/v1", KEY)
        with self.assertRaises(llm.ProviderError) as ctx:
            llm.generate(config, "s", "u")
        self.assertIn("Could not connect", str(ctx.exception))


class ValidationTests(Base):
    def test_rules(self):
        cases = {
            ("openai", "gpt-5", "http://example.com/v1", KEY): "HTTPS",
            ("openai", "gpt-5", "https://u:p@example.com/v1", KEY): "credentials",
            ("openai", "gpt-5", "https://example.com/v1?x=1", KEY): "query",
            ("openai", "", "https://example.com/v1", KEY): "model name",
            ("openai", "bad model", "https://example.com/v1", KEY): "unsupported characters",
            ("anthropic", "claude", "https://example.com/v1", ""): "API key",
            ("openai", "gpt-5", "https://example.com/v1", "sk abc"): "whitespace",
            ("mystery", "m", "https://example.com/v1", KEY): "provider",
            ("compatible", "m", "", ""): "base URL",
        }
        for args, message in cases.items():
            with self.subTest(args), self.assertRaisesRegex(ValueError, message):
                llm.validate(llm.LLMConfig(*args))

    def test_no_default_model(self):
        for provider in llm.PROVIDERS:
            self.assertEqual(llm.resolve_config(provider).model, "")
        with self.assertRaisesRegex(ValueError, "Enter a model name"):
            llm.validate(llm.LLMConfig("openai", "", "", KEY))
        with self.assertRaisesRegex(ValueError, "Enter a model name"):
            llm.generate(self.cfg("openai", ""), "s", "u")

    def test_check_without_model_lists_models(self):
        events = []
        ok, models = llm.check_connection(self.cfg("openai", ""), lambda *a: events.append(a))
        self.assertFalse(ok)
        self.assertEqual(models, ["gpt-5", "gpt-5-mini"])
        self.assertEqual([e[3] for e in events if e[3] != "run"], ["ok", "ok", "ok", "fail"])
        self.assertIn("Your key can use: gpt-5, gpt-5-mini", events[-1][4])

    def test_defaults_and_normalization(self):
        c = llm.validate(llm.LLMConfig("gemini", "models/gemini-x", "", KEY))
        self.assertEqual((c.model, c.base_url), ("gemini-x", llm.PROVIDERS["gemini"].base_url))
        self.assertEqual(llm.validate(llm.LLMConfig("openai", "m", "https://a.example/v1/", KEY)).base_url,
                         "https://a.example/v1")
        self.assertNotIn(KEY, repr(llm.LLMConfig("openai", "m", "u", KEY)))


class ConfigTests(Base):
    def test_save_load_permissions_and_remember(self):
        path = llm.save_config(llm.LLMConfig("anthropic", "claude-opus-5-5", "https://proxy.example/v1", KEY))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        resolved = llm.resolve_config()
        self.assertEqual((resolved.provider, resolved.model, resolved.base_url, resolved.api_key),
                         ("anthropic", "claude-opus-5-5", "https://proxy.example/v1", KEY))
        llm.save_config(llm.LLMConfig("anthropic", "claude-opus-5-5", "", KEY), remember_key=False)
        self.assertNotIn(KEY, path.read_text())
        self.assertEqual(llm.resolve_config().base_url, llm.PROVIDERS["anthropic"].base_url)

    def test_per_provider_settings_kept(self):
        llm.save_config(llm.LLMConfig("openai", "gpt-5-mini", "", "k1"))
        llm.save_config(llm.LLMConfig("gemini", "gemini-2.5-pro", "", "k2"))
        self.assertEqual(llm.resolve_config().provider, "gemini")
        self.assertEqual(llm.resolve_config("openai").api_key, "k1")

    def test_env_precedence_and_backward_compat(self):
        os.environ["THREATDOCKET_LLM_BASE_URL"] = "https://legacy.example/v1"
        os.environ["THREATDOCKET_LLM_MODEL"] = "legacy"
        c = llm.resolve_config()
        self.assertEqual((c.provider, c.base_url, c.model), ("compatible", "https://legacy.example/v1", "legacy"))
        # generic overrides must not leak into a different provider
        self.assertEqual(llm.resolve_config("anthropic").base_url, llm.PROVIDERS["anthropic"].base_url)
        os.environ["ANTHROPIC_API_KEY"] = "ant-key"
        os.environ["THREATDOCKET_LLM_PROVIDER"] = "anthropic"
        del os.environ["THREATDOCKET_LLM_BASE_URL"], os.environ["THREATDOCKET_LLM_MODEL"]
        self.assertEqual(llm.resolve_config().api_key, "ant-key")
        self.assertEqual(llm.resolve_config(model="x", base_url="https://b.example").model, "x")

    def test_legacy_atlas_variables_still_work(self):
        os.environ["ATLAS_LLM_BASE_URL"] = "https://legacy.example/v1"
        os.environ["ATLAS_LLM_MODEL"] = "legacy"
        c = llm.resolve_config()
        self.assertEqual((c.provider, c.base_url, c.model), ("compatible", "https://legacy.example/v1", "legacy"))
        os.environ["THREATDOCKET_LLM_MODEL"] = "new"  # new name wins
        self.assertEqual(llm.resolve_config().model, "new")

    def test_corrupt_config_ignored(self):
        llm.config_path().parent.mkdir(parents=True, exist_ok=True)
        llm.config_path().write_text("{not json")
        self.assertEqual(llm.resolve_config().provider, "openai")


class CheckAndAdviceTests(Base):
    def run_check(self, config):
        events = []
        ok, models = llm.check_connection(config, lambda *a: events.append(a))
        return ok, models, [(e[2], e[3]) for e in events if e[3] != "run"]

    def test_full_check_each_provider(self):
        for provider, model in (("openai", "gpt-5"), ("anthropic", "claude-sonnet-5-5"),
                                ("gemini", "gemini-2.5-flash")):
            with self.subTest(provider):
                ok, models, steps = self.run_check(self.cfg(provider, model))
                self.assertTrue(ok, steps)
                self.assertEqual([s for _l, s in steps], ["ok"] * 5)
                self.assertTrue(models)

    def test_check_stops_at_bad_key(self):
        ok, _m, steps = self.run_check(self.cfg("anthropic", "claude-sonnet-5-5", key="bad"))
        self.assertFalse(ok)
        self.assertEqual(steps[-1], ("Authenticate and list models", "fail"))
        self.assertEqual(len(steps), 3)

    def test_check_warns_on_unlisted_model_then_fails_generation(self):
        ok, _m, steps = self.run_check(self.cfg("openai", "gpt-nope"))
        self.assertFalse(ok)
        self.assertEqual([s for _l, s in steps], ["ok", "ok", "ok", "warn", "fail"])

    def test_compatible_without_listing_warns_but_passes(self):
        ok, models, steps = self.run_check(self.cfg("compatible", "llama", key=""))
        self.assertTrue(ok)
        self.assertEqual([s for _l, s in steps], ["ok", "ok", "warn", "warn", "ok"])

    def test_invalid_settings_fail_first_step(self):
        ok, _m, steps = self.run_check(llm.LLMConfig("openai", "gpt-5", "http://evil.example/v1", KEY))
        self.assertFalse(ok)
        self.assertEqual(steps, [("Validate settings", "fail")])

    def test_advisory_sends_only_redacted_summary(self):
        events = []
        text = llm.advisory(self.report, self.cfg("anthropic", "claude-sonnet-5-5"), lambda *a: events.append(a))
        self.assertEqual(text, "OK from Claude")
        self.assertEqual([e[3] for e in events if e[3] != "run"], ["ok"] * 4)
        sent = json.loads(Handler.log[-1]["body"]["messages"][0]["content"])
        self.assertEqual(set(sent), {"atlas_version", "rule_counts", "control_outcome_counts"})
        blob = json.dumps(Handler.log[-1]["body"])
        for finding in self.report["findings"]:
            self.assertNotIn(finding["path"], blob)

    def test_advisory_failure_reports_step(self):
        events = []
        with self.assertRaisesRegex(ValueError, "did not return a usable advisory"):
            llm.advisory(self.report, self.cfg("openai", "gpt-5", key="bad"), lambda *a: events.append(a))
        self.assertEqual(events[-1][3], "fail")


class CLITests(Base):
    def test_check_llm_and_advise(self):
        llm.save_config(self.cfg("gemini", "gemini-2.5-flash"))
        with mock.patch("sys.stdout") as out:
            self.assertEqual(main(["check-llm"]), 0)
        printed = "".join(c.args[0] for c in out.write.call_args_list)
        self.assertIn("5/5 ✓ Test generation", printed)
        self.assertIn("All checks passed", printed)
        with mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            self.assertEqual(main(["check-llm", "--model", "nope-model"]), 1)
            self.assertEqual(main(["advise", str(EXAMPLES / "demo"), "--provider", "anthropic"]), 2)  # no model
            self.assertEqual(main(["advise", str(EXAMPLES / "demo"), "--provider", "openai", "--model", "gpt-5",
                                   "--base-url", self.url + "/openai/v1"]), 2)  # no OpenAI key saved
        os.environ["OPENAI_API_KEY"] = KEY
        with mock.patch("sys.stdout") as out, mock.patch("sys.stderr"):
            self.assertEqual(main(["advise", str(EXAMPLES / "demo"), "--provider", "openai", "--model", "gpt-5",
                                   "--base-url", self.url + "/openai/v1"]), 0)
        self.assertIn("OK from GPT", "".join(c.args[0] for c in out.write.call_args_list))


if __name__ == "__main__":
    unittest.main()
