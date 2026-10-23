"""Backend seams for browser / web / terminal backend plugins.

A plugin that wraps an external surface (a browser server, a web API, a sandbox) needs the same URL
policy, secret redaction and cache-path translation Hermes applies to its own built-in tools.
Before these existed such plugins imported core internals (``tools.browser_url_policy``,
``agent.redact``, ``tools.credential_files``) with no plugin seam, so a core refactor that moved a
private name broke the plugin on an unrelated release (catalog rule 9). These delegate to the live
core implementation, so a plugin tracks core's policy without importing it.

``PluginContext`` mixes this in; see developer-guide/backend-seams.md.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class BackendSeamsMixin:
    """Public ``ctx`` methods a backend plugin uses instead of importing core internals."""

    def register_redaction_patterns(self, patterns) -> int:
        """Additively register secret-token regexes with :mod:`agent.redact`; returns the count accepted.
        Plugins can over-redact, never weaken built-ins; ``security.redact_secrets: false`` applies
        equally. Each pattern must compile and start with >= 2 literal characters; invalid entries warn
        and are skipped."""
        from agent.redact import register_redaction_patterns as _register
        try:
            count = _register(patterns, source=f"plugin:{self.manifest.name}")
        except Exception as exc:
            logger.warning("Plugin '%s' redaction pattern registration failed: %s", self.manifest.name, exc)
            return 0
        logger.debug("Plugin %s registered %d redaction pattern(s)", self.manifest.name, count)
        return count

    def redact_text(
        self, text: str, *, force: bool = False, code_file: bool = False,
        file_read: bool = False, secret_file: bool = False,
        redact_url_credentials: bool = False,
    ) -> str:
        """Apply Hermes's secret redaction to text a plugin is about to hand the model -- tool
        output, a page snapshot, a screenshot caption. Honours ``security.redact_secrets`` and
        covers the vault plus patterns registered via :meth:`register_redaction_patterns`. ``force``
        redacts secret-shaped values even when passive redaction is off (use for backend output the
        user never typed); the remaining flags select the file/URL redaction modes core uses.
        Plugins can over-redact, never weaken built-ins. A faithful replacement for importing
        ``agent.redact.redact_sensitive_text``."""
        from agent.redact import redact_sensitive_text
        return redact_sensitive_text(
            str(text or ""), force=force, code_file=code_file, file_read=file_read,
            secret_file=secret_file, redact_url_credentials=redact_url_credentials,
        )

    def evaluate_url_safety(self, url: str, *, auto_local: bool = False) -> Optional[dict]:
        """``None`` if ``url`` is safe for a browser/web backend to open, else an error dict
        (``{"success": False, "error": ..., ...}``) ready to return to the model. Applies the same
        ordered floors as core's own browser, for the active backend: cloud-metadata/IMDS refused
        unconditionally, then private/internal addresses (unless the backend is local or
        ``browser.allow_private_urls``), then the ``security.website_blocklist`` allow/deny policy,
        and it refuses URLs that embed a Hermes secret. ``auto_local=True`` -- the URL will be
        opened by a local browser (a hybrid local sidecar, or a plugin whose backend is itself a
        local browser) -- relaxes only the private-address floor, never the metadata one. A
        faithful replacement for importing ``tools.browser_url_policy.evaluate_url_safety``."""
        from tools.browser_url_policy import evaluate_url_safety
        return evaluate_url_safety(url, auto_local=auto_local)

    def normalize_request_url(self, url: str) -> str:
        """ASCII-normalize a URL the way core does before handing it to a browser/HTTP backend
        (IDN host to punycode, non-ASCII path/query percent-encoded), so a backend plugin sends the
        same wire form core's own browser would and matches what :meth:`evaluate_url_safety`
        checked. A faithful replacement for importing ``tools.url_safety.normalize_url_for_request``."""
        from tools.url_safety import normalize_url_for_request
        return normalize_url_for_request(url)

    def agent_visible_cache_path(self, host_path: str, container_base: str = "/root/.hermes") -> str:
        """Translate a host cache path (a saved screenshot, snapshot or download under the Hermes
        home) to where the active terminal backend sees it -- docker/modal mount at
        ``/root/.hermes``, ssh/daytona under ``~/.hermes``, plugin backends by their declared
        ``cache_path_base``, local unchanged -- so a path the plugin reports to the model is one the
        model's terminal tools can actually open. A faithful replacement for importing
        ``tools.credential_files.to_agent_visible_cache_path``."""
        from tools.credential_files import to_agent_visible_cache_path
        return to_agent_visible_cache_path(host_path, container_base=container_base)

    def core_bundles_tool(self, tool_name: str) -> bool:
        """True when the running Hermes core still ships a built-in tool module ``tools.<tool_name>``,
        resolved on the package path WITHOUT importing the module. A plugin migrating a capability
        out of core uses it to stay inert on an older core that still bundles the built-in, so
        installing the plugin early never registers the tool twice. Replaces the
        ``importlib ... tools.__path__`` probe plugins hand-rolled against the private ``tools``
        package."""
        from importlib.machinery import PathFinder
        try:
            import tools
            return PathFinder.find_spec(f"tools.{tool_name}", list(tools.__path__)) is not None
        except (ImportError, AttributeError, ValueError):
            return False
