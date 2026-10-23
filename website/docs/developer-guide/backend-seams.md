---
sidebar_position: 19
title: "Backend Seams"
description: "Reuse Hermes's own URL policy, secret redaction and cache-path translation from a browser/web/terminal backend plugin via ctx — without importing core internals that move between releases."
---

# Backend Seams

A plugin that wraps an external surface — a browser server, a web API, a
sandbox — usually needs the same guardrails Hermes applies to its own
built-in tools: block a request to a cloud-metadata endpoint, keep a secret
out of a URL, redact an API key before a page snapshot reaches the model,
report a file path the model's terminal can actually open.

Those guardrails live in core. Before these seams existed, a backend plugin
reached into them directly — `tools.browser_url_policy`, `agent.redact`,
`tools.credential_files` — none of which is a documented plugin surface. That
works until a core release moves a private name, and then the plugin breaks on
a release that had nothing to do with it ([catalog rule 9](plugins/catalog-submission.md):
public surfaces only).

`ctx` now exposes the policy itself, not the module. Each seam delegates to the
live core implementation, so the plugin tracks core's behaviour — including
config like `browser.allow_private_urls` and `security.website_blocklist` — without
importing anything private.

## URL safety

```python
blocked = ctx.evaluate_url_safety(url)
if blocked is not None:
    return blocked  # {"success": False, "error": "...", ...} — ready to return to the model
```

`evaluate_url_safety(url, *, auto_local=False)` returns `None` when the URL is
safe for the **active backend** to open, otherwise an error dict you can hand
straight back to the model. It applies the same ordered floors as Hermes's own
browser:

1. **Cloud metadata / IMDS** (`169.254.169.254`, `metadata.google.internal`, …)
   — refused unconditionally. A local Chromium on a cloud VM still reaches the
   host's credentials endpoint.
2. **Private / internal addresses** — refused unless the backend is local, the
   URL will be opened by a local browser (`auto_local=True`), or
   `browser.allow_private_urls` is set.
3. **Website allow/deny policy** — `security.website_blocklist`.
4. **Secrets in the URL** — a URL that embeds something shaped like an API key
   or token is refused (raw and percent-decoded), so a prompt injection can't
   exfiltrate a secret through a navigation.

Pass `auto_local=True` when the URL will be opened by a local browser — a
hybrid local sidecar, or a plugin whose backend is itself a local browser
(Camofox does this). It relaxes the private-address floor and nothing else;
the metadata, blocklist and secret-in-URL floors still apply.

To send a backend the same wire form Hermes's own browser would — and to match
what `evaluate_url_safety` checked — normalize first:

```python
blocked = ctx.evaluate_url_safety(url, auto_local=True)
if blocked is not None:
    return blocked
wire_url = ctx.normalize_request_url(url)  # IDN host to punycode, non-ASCII path/query percent-encoded
```

`normalize_request_url(url)` is the public form of core's
`normalize_url_for_request`.

## Secret redaction

```python
safe = ctx.redact_text(page_text)
```

`redact_text(text, *, force=False, code_file=False, file_read=False,
secret_file=False, redact_url_credentials=False)` runs text a plugin is about
to hand the model through Hermes's redactor. It honours
`security.redact_secrets` and covers the vault plus any patterns the plugin
registered with `ctx.register_redaction_patterns`. Use
`force=True` for backend output the user never typed (a page snapshot, a
console log) so secret-shaped values are redacted even when passive redaction
is off. Plugins can over-redact, never weaken the built-ins.

## Cache-path translation

```python
model_path = ctx.agent_visible_cache_path(saved_png_path)
return {"success": True, "path": model_path}
```

When a backend saves an artifact (a screenshot, a snapshot, a download) under
the Hermes home and reports the path to the model, the model's terminal may see
that path at a different mount — docker and modal at `/root/.hermes`, ssh and
daytona under `~/.hermes`, a plugin terminal backend at its declared
`cache_path_base`, local unchanged. `agent_visible_cache_path(host_path)`
returns the path the active terminal backend can actually open.

## Staying inert on older core

A plugin that is migrating a capability **out** of core must not register its
tool on a Hermes that still bundles the built-in, or the tool is registered
twice.

```python
def register(ctx):
    if ctx.core_bundles_tool("browser_camofox"):
        return  # this core still ships the built-in; stay inert
    ctx.register_tool(...)
```

`core_bundles_tool(name)` is `True` when the running core still ships a built-in
`tools.<name>`, resolved on the package path **without importing the module**.

## Why go through `ctx`

Every seam here could be reproduced by importing the core module it wraps, and
some plugins did. The cost is invisible until it isn't: the import passes
review, the plugin ships, and six weeks later a core refactor that renamed a
private helper breaks a browser plugin in a release whose changelog never
mentions the browser. Going through `ctx` means the plugin depends on a surface
Hermes promises to keep, and the policy the plugin enforces is always the
policy core is enforcing right now — not a copy that drifted.
