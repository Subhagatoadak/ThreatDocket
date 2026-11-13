"""A loopback HTTP server that emulates the OpenAI, Anthropic and Gemini APIs for tests."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading

KEY = "sk-test-KEY-123456"


class Handler(BaseHTTPRequestHandler):
    log = []

    def log_message(self, *args):
        pass

    def _send(self, code, payload, headers=None):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length)) if length else None

    def _deny(self):
        # Echo the bad key back to prove the client redacts it.
        self._send(401, {"error": {"message": f"Incorrect API key provided: {self._key()}"}})

    def _key(self):
        auth = self.headers.get("Authorization", "")
        return (auth.removeprefix("Bearer ") or self.headers.get("x-api-key")
                or self.headers.get("x-goog-api-key") or "")

    def handle_any(self, method):
        body = self._body() if method == "POST" else None
        Handler.log.append({"method": method, "path": self.path, "headers": dict(self.headers), "body": body})
        path = self.path
        if path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.end_headers()
            return
        if path.startswith("/html"):
            data = b"<html>not json</html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if path.startswith("/openai/v1"):
            if self.headers.get("Authorization") != "Bearer " + KEY:
                return self._deny()
            if path == "/openai/v1/models":
                return self._send(200, {"data": [{"id": "gpt-5"}, {"id": "gpt-5-mini"}]})
            if path == "/openai/v1/chat/completions":
                if body["model"] not in {"gpt-5", "gpt-5-mini"}:
                    return self._send(404, {"error": {"message": f"The model {body['model']} does not exist"}})
                return self._send(200, {"choices": [{"message": {"content": "OK from GPT"}}]})
        if path.startswith("/anthropic/v1"):
            if self.headers.get("x-api-key") != KEY or self.headers.get("anthropic-version") != "2023-06-01":
                return self._deny()
            if path.startswith("/anthropic/v1/models"):
                return self._send(200, {"data": [{"id": "claude-sonnet-5-5"}, {"id": "claude-opus-5-5"}]})
            if path == "/anthropic/v1/messages":
                assert body["system"] and body["max_tokens"]
                return self._send(200, {"content": [{"type": "text", "text": "OK from Claude"}]})
        if path.startswith("/gemini/v1beta"):
            if self.headers.get("x-goog-api-key") != KEY:
                return self._send(403, {"error": {"code": 403, "message": "API key not valid", "status": "PERMISSION_DENIED"}})
            if path.startswith("/gemini/v1beta/models?"):
                if "pageToken=p2" in path:
                    return self._send(200, {"models": [{"name": "models/gemini-2.5-pro", "supportedGenerationMethods": ["generateContent"]}]})
                return self._send(200, {"models": [
                    {"name": "models/gemini-2.5-flash", "supportedGenerationMethods": ["generateContent"]},
                    {"name": "models/text-embedding-004", "supportedGenerationMethods": ["embedContent"]},
                ], "nextPageToken": "p2"})
            if path.endswith(":generateContent"):
                if not path.startswith("/gemini/v1beta/models/gemini-2.5-"):
                    return self._send(404, {"error": {"code": 404, "message": "models/x is not found", "status": "NOT_FOUND"}})
                assert body["systemInstruction"]["parts"][0]["text"]
                return self._send(200, {"candidates": [{"content": {"parts": [
                    {"text": "hidden", "thought": True}, {"text": "OK from Gemini"}]}}]})
        if path.startswith("/compat/v1"):
            if path == "/compat/v1/chat/completions":
                return self._send(200, {"choices": [{"message": {"content": "OK from compatible"}}]})
            return self._send(404, {"error": "not found"})
        self._send(404, {"error": {"message": "unknown path"}})

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")


def start():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"
