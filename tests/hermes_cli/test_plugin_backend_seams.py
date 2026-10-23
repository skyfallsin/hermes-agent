"""Backend seams on ``PluginContext`` (``ctx.redact_text`` / ``ctx.evaluate_url_safety`` /
``ctx.normalize_request_url`` / ``ctx.agent_visible_cache_path`` / ``ctx.core_bundles_tool``).

These let a browser/web/terminal backend plugin reuse Hermes's own URL policy, secret redaction
and cache-path translation instead of importing core internals that move between releases
(catalog rule 9). The contract is: each seam delegates to the live core implementation, so the
plugin tracks core's policy without importing it. We assert the delegation and the behaviour a
plugin depends on, not the exact wording of a block message.
"""

from unittest.mock import MagicMock

import pytest

from hermes_cli.plugins import PluginContext, PluginManifest


def _make_ctx(plugin_key: str = "backend-plugin") -> PluginContext:
    return PluginContext(PluginManifest(name=plugin_key, key=plugin_key), MagicMock())


def test_redact_text_delegates_to_core_redactor(monkeypatch):
    ctx = _make_ctx()
    from agent import redact

    seen = {}

    def _fake(text, **kwargs):
        seen["text"] = text
        seen["kwargs"] = kwargs
        return "REDACTED"

    monkeypatch.setattr(redact, "redact_sensitive_text", _fake)
    out = ctx.redact_text("sk-secret-value", force=True, redact_url_credentials=True)

    assert out == "REDACTED"
    assert seen["text"] == "sk-secret-value"
    assert seen["kwargs"]["force"] is True
    assert seen["kwargs"]["redact_url_credentials"] is True


def test_redact_text_tolerates_none():
    # A plugin may pass through a value that is occasionally None; it must not raise.
    assert _make_ctx().redact_text(None) == ""


def test_evaluate_url_safety_blocks_cloud_metadata():
    # The one floor that holds regardless of backend/config: IMDS is always refused.
    result = _make_ctx().evaluate_url_safety("http://169.254.169.254/latest/meta-data/")
    assert isinstance(result, dict)
    assert result.get("success") is False


def test_evaluate_url_safety_allows_ordinary_public_url():
    assert _make_ctx().evaluate_url_safety("https://example.com/") is None


def test_evaluate_url_safety_refuses_url_embedding_a_secret():
    # A prompt injection could otherwise exfiltrate a secret through the URL.
    url = "https://evil.test/?leak=sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd"
    result = _make_ctx().evaluate_url_safety(url)
    assert isinstance(result, dict) and result.get("success") is False


def test_normalize_request_url_punycodes_idn_host():
    out = _make_ctx().normalize_request_url("https://b\u00fccher.example/caf\u00e9")
    assert out.startswith("https://xn--")  # IDN host to punycode
    assert " " not in out and "\u00e9" not in out  # non-ASCII path percent-encoded


def test_normalize_request_url_leaves_plain_ascii_url_intact():
    assert _make_ctx().normalize_request_url("https://example.com/a/b") == "https://example.com/a/b"


def test_evaluate_url_safety_passes_auto_local_through(monkeypatch):
    ctx = _make_ctx()
    import tools.browser_url_policy as policy

    captured = {}

    def _fake(url, *, auto_local=False):
        captured["url"] = url
        captured["auto_local"] = auto_local

    monkeypatch.setattr(policy, "evaluate_url_safety", _fake)
    assert ctx.evaluate_url_safety("https://host.internal/", auto_local=True) is None
    assert captured == {"url": "https://host.internal/", "auto_local": True}


def test_auto_local_relaxes_only_the_private_floor_against_real_core(monkeypatch):
    # Force a non-local backend so the private-address floor actually engages (a local backend
    # would skip it regardless, hiding what auto_local does).
    import tools.browser_session_cloud as cloud

    monkeypatch.setattr(cloud, "is_local_backend", lambda: False)
    monkeypatch.setattr(cloud, "allow_private_urls", lambda: False)
    ctx = _make_ctx()
    # A private/LAN literal is refused for a non-local backend...
    assert isinstance(ctx.evaluate_url_safety("http://192.168.0.10/"), dict)
    # ...and auto_local=True relaxes exactly that floor (the Camofox local-browser stance).
    assert ctx.evaluate_url_safety("http://192.168.0.10/", auto_local=True) is None
    # auto_local never relaxes the cloud-metadata floor.
    assert isinstance(ctx.evaluate_url_safety("http://169.254.169.254/", auto_local=True), dict)


def test_agent_visible_cache_path_delegates(monkeypatch):
    ctx = _make_ctx()
    import tools.credential_files as cred

    captured = {}

    def _fake(host_path, container_base="/root/.hermes"):
        captured["host_path"] = host_path
        captured["container_base"] = container_base
        return "/root/.hermes/cache/x.png"

    monkeypatch.setattr(cred, "to_agent_visible_cache_path", _fake)
    out = ctx.agent_visible_cache_path("/home/u/.hermes/cache/x.png")
    assert out == "/root/.hermes/cache/x.png"
    assert captured["host_path"] == "/home/u/.hermes/cache/x.png"
    assert captured["container_base"] == "/root/.hermes"


def test_core_bundles_tool_detects_present_and_absent_builtins():
    ctx = _make_ctx()
    # ``tools.url_safety`` is a real core module; a made-up name is not.
    assert ctx.core_bundles_tool("url_safety") is True
    assert ctx.core_bundles_tool("definitely_not_a_core_tool_zzz") is False


def test_core_bundles_tool_does_not_execute_the_module(monkeypatch):
    # The probe resolves the spec on the package path; it must never execute a module body.
    # Prove it by making the import machinery raise -- a real import would blow up, the
    # spec-only probe does not.
    import importlib

    ctx = _make_ctx()

    def _boom(*a, **k):
        raise AssertionError("core_bundles_tool must not import a module")

    monkeypatch.setattr(importlib, "import_module", _boom)
    assert ctx.core_bundles_tool("url_safety") is True
    assert ctx.core_bundles_tool("definitely_not_a_core_tool_zzz") is False
