import asyncio
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from textual.widgets import Button, DataTable, Input, Markdown, ProgressBar, Select, Static, TabbedContent

from threatdocket import advisory as llm
from threatdocket.review import review
from threatdocket.tui import Dashboard

from mock_providers import KEY, start

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
SHOTS = os.getenv("THREATDOCKET_TEST_SCREENSHOTS")


class AdvisorTabTests(unittest.IsolatedAsyncioTestCase):
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
        env = {k: v for k, v in os.environ.items() if not k.startswith(("ATLAS_", "THREATDOCKET_")) and not k.endswith("_API_KEY")}
        self.env = mock.patch.dict(os.environ, dict(env, THREATDOCKET_CONFIG_DIR=self.tmp.name), clear=True)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    async def wait_idle(self, app, pilot):
        await app.workers.wait_for_complete()
        await pilot.pause()

    def shot(self, app, name):
        if SHOTS:
            app.save_screenshot(filename=name + ".svg", path=SHOTS)

    def text(self, app, selector):
        return str(app.query_one(selector, Static).render())

    async def test_configure_check_run_and_switch(self):
        app = Dashboard(self.report)
        async with app.run_test(size=(150, 48)) as pilot:
            app.query_one(TabbedContent).active = "advisor"
            await pilot.pause()
            # Defaults for a fresh install
            self.assertEqual(app.query_one("#llm-provider", Select).value, "openai")
            self.assertEqual(app.query_one("#llm-base-url", Input).value, "https://api.openai.com/v1")
            self.assertTrue(app.query_one("#llm-api-key", Input).password)

            # Switch to Claude, override the base URL, paste a key
            app.query_one("#llm-provider", Select).value = "anthropic"
            await pilot.pause()
            self.assertEqual(app.query_one("#llm-model", Input).value, "")  # no default model
            self.assertEqual(app.query_one("#llm-base-url", Input).value, "https://api.anthropic.com/v1")
            app.query_one("#llm-base-url", Input).value = self.url + "/anthropic/v1"
            app.query_one("#llm-api-key", Input).value = KEY

            # Check with no model: key is verified, then the available models are listed
            await pilot.click("#llm-check")
            await self.wait_idle(app, pilot)
            steps = self.text(app, "#llm-steps")
            self.assertIn("Enter a model name. Your key can use: claude-opus-5-5, claude-sonnet-5-5", steps)
            self.assertIn("Check failed", self.text(app, "#llm-status"))
            self.shot(app, "0-no-model")
            await pilot.press("ctrl+r")
            await self.wait_idle(app, pilot)
            self.assertIn("Enter a model name", self.text(app, "#llm-steps"))
            app.query_one("#llm-model", Input).value = "claude-sonnet-5-5"
            await pilot.click("#llm-show-key")
            self.assertFalse(app.query_one("#llm-api-key", Input).password)
            await pilot.click("#llm-show-key")

            # Thorough check with progress bar
            await pilot.click("#llm-check")
            await self.wait_idle(app, pilot)
            bar = app.query_one("#llm-progress", ProgressBar)
            self.assertEqual((bar.progress, bar.total), (5, 5))
            steps = self.text(app, "#llm-steps")
            self.assertEqual(steps.count("✓"), 5, steps)
            self.assertIn("All checks passed", self.text(app, "#llm-status"))
            self.assertFalse(app.query_one("#llm-run", Button).disabled)
            self.shot(app, "1-check-passed")
            # Successful check auto-saves settings (key remembered by default)
            saved = llm.resolve_config()
            self.assertEqual((saved.provider, saved.base_url, saved.api_key),
                             ("anthropic", self.url + "/anthropic/v1", KEY))

            # Run the advisory
            await pilot.click("#llm-run")
            await self.wait_idle(app, pilot)
            await pilot.pause(0.2)
            self.assertEqual(app.query_one("#llm-progress", ProgressBar).progress, 4)
            self.assertIn("Advisory received", self.text(app, "#llm-status"))
            self.assertIn("OK from Claude", app.query_one("#llm-result", Markdown).source)
            self.assertEqual(app.query_one(TabbedContent).active, "ai-findings")  # auto-opened
            self.assertIn("claude-sonnet-5-5", str(app.query_one("#ai-meta", Static).render()))
            self.shot(app, "2-advisory")
            app.query_one(TabbedContent).active = "advisor"
            await pilot.pause()

            # Switch to Gemini with a wrong key: check must stop at authentication
            app.query_one("#llm-provider", Select).value = "gemini"
            await pilot.pause()
            app.query_one("#llm-base-url", Input).value = self.url + "/gemini/v1beta"
            app.query_one("#llm-api-key", Input).value = "wrong-key"
            app.query_one("#llm-model", Input).value = "gemini-2.5-flash"
            await pilot.click("#llm-check")
            await self.wait_idle(app, pilot)
            steps = self.text(app, "#llm-steps")
            self.assertIn("✗", steps)
            self.assertIn("HTTP 403", steps)
            self.assertNotIn("wrong-key", steps)
            self.assertEqual(app.query_one("#llm-progress", ProgressBar).progress, 2)
            self.assertIn("Check failed", self.text(app, "#llm-status"))
            self.shot(app, "3-check-failed")

            # Switching back restores the Claude draft (not the Gemini edits)
            app.query_one("#llm-provider", Select).value = "anthropic"
            await pilot.pause()
            self.assertEqual(app.query_one("#llm-base-url", Input).value, self.url + "/anthropic/v1")
            self.assertEqual(app.query_one("#llm-api-key", Input).value, KEY)

            # Save without remembering the key
            await pilot.click("#llm-remember")
            await pilot.click("#llm-save")
            await pilot.pause()
            self.assertIn("API key not stored", self.text(app, "#llm-status"))
            self.assertNotIn(KEY, llm.config_path().read_text())

    async def test_saved_settings_prefill_and_validation_error(self):
        llm.save_config(llm.LLMConfig("gemini", "gemini-2.5-flash", self.url + "/gemini/v1beta", KEY))
        app = Dashboard(self.report)
        async with app.run_test(size=(150, 48)) as pilot:
            app.query_one(TabbedContent).active = "advisor"
            await pilot.pause()
            self.assertEqual(app.query_one("#llm-provider", Select).value, "gemini")
            self.assertEqual(app.query_one("#llm-api-key", Input).value, KEY)
            app.query_one("#llm-api-key", Input).focus()
            await pilot.press("ctrl+t")  # shortcut works while typing in a field
            await self.wait_idle(app, pilot)
            self.assertEqual(self.text(app, "#llm-steps").count("✓"), 5)
            # Invalid URL fails in step 1, and run reports it too
            app.query_one("#llm-base-url", Input).value = "http://not-local.example/v1"
            await pilot.press("ctrl+r")
            await self.wait_idle(app, pilot)
            self.assertIn("HTTPS", self.text(app, "#llm-steps"))
            self.assertIn("Advisory failed", self.text(app, "#llm-status"))

    async def test_existing_filters_still_work(self):
        app = Dashboard(self.report)
        async with app.run_test(size=(150, 48)) as pilot:
            app.query_one(TabbedContent).active = "cases"
            await pilot.pause()
            table = app.query_one("#table-cases", DataTable)
            before = table.row_count
            app.query_one("#search-cases", Input).value = "AML.CS0000"
            await pilot.pause()
            self.assertLess(table.row_count, before)
            # Typing in advisor inputs must not touch tables
            app.query_one("#llm-model", Input).value = "anything"
            await pilot.pause()


if __name__ == "__main__":
    unittest.main()
