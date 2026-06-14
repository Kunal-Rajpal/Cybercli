"""
CyberCLI Proxy Supporting Modules
request_parser.py · response_parser.py · interceptor.py
session_manager.py · traffic_logger.py · tls_handler.py
"""

# ─── request_parser.py ────────────────────────────────────────────────────────

import re
import logging
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Optional

logger = logging.getLogger("cybercli.proxy")


@dataclass
class ParsedRequest:
    method: str
    url: str
    path: str
    version: str
    headers: Dict[str, str]
    body: bytes
    params: Dict[str, str] = field(default_factory=dict)
    raw: bytes = b""


class RequestParser:
    def parse(self, raw: bytes) -> Optional[ParsedRequest]:
        try:
            if b"\r\n\r\n" in raw:
                header_part, body = raw.split(b"\r\n\r\n", 1)
            else:
                header_part, body = raw, b""

            lines = header_part.decode("utf-8", errors="ignore").split("\r\n")
            if not lines:
                return None

            request_line = lines[0].split()
            if len(request_line) < 3:
                return None

            method, path, version = request_line[0], request_line[1], request_line[2]

            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()

            host = headers.get("Host", "")
            if path.startswith("http"):
                url = path
            else:
                scheme = "https" if "443" in host else "http"
                url = f"{scheme}://{host}{path}"

            # Parse query params
            params = {}
            if "?" in path:
                qs = path.split("?", 1)[1]
                params = dict(urllib.parse.parse_qsl(qs))

            return ParsedRequest(
                method=method,
                url=url,
                path=path,
                version=version,
                headers=headers,
                body=body,
                params=params,
                raw=raw,
            )
        except Exception as e:
            logger.debug(f"[PARSER] Request parse error: {e}")
            return None


# ─── response_parser.py ───────────────────────────────────────────────────────

from dataclasses import dataclass as _dc


@_dc
class ParsedResponse:
    status: int
    reason: str
    version: str
    headers: Dict[str, str]
    body: bytes
    raw: bytes = b""


class ResponseParser:
    def parse(self, raw: bytes) -> Optional[ParsedResponse]:
        try:
            if b"\r\n\r\n" in raw:
                header_part, body = raw.split(b"\r\n\r\n", 1)
            else:
                header_part, body = raw, b""

            lines = header_part.decode("utf-8", errors="ignore").split("\r\n")
            status_line = lines[0].split(None, 2)
            version = status_line[0] if len(status_line) > 0 else "HTTP/1.1"
            status = int(status_line[1]) if len(status_line) > 1 else 200
            reason = status_line[2] if len(status_line) > 2 else "OK"

            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()

            return ParsedResponse(
                status=status,
                reason=reason,
                version=version,
                headers=headers,
                body=body,
                raw=raw,
            )
        except Exception as e:
            logger.debug(f"[PARSER] Response parse error: {e}")
            return None

    def from_urllib(self, resp) -> ParsedResponse:
        """Convert urllib response to ParsedResponse"""
        try:
            body = resp.read()
            headers = dict(resp.headers)
            return ParsedResponse(
                status=resp.status,
                reason=resp.reason,
                version="HTTP/1.1",
                headers=headers,
                body=body,
                raw=b"",
            )
        except Exception:
            return ParsedResponse(200, "OK", "HTTP/1.1", {}, b"")


# ─── interceptor.py ───────────────────────────────────────────────────────────

import base64 as _b64
import json as _json
from typing import Callable, List as _List


class Interceptor:
    """
    Request/Response interceptor.
    Supports: header modification, JWT tampering, body mutation, replay injection.
    All operations are non-destructive by default.
    """

    def __init__(self):
        self._request_hooks: _List[Callable] = []
        self._response_hooks: _List[Callable] = []

    def add_request_hook(self, fn: Callable):
        self._request_hooks.append(fn)

    def add_response_hook(self, fn: Callable):
        self._response_hooks.append(fn)

    def process_request(self, req: ParsedRequest) -> ParsedRequest:
        for hook in self._request_hooks:
            try:
                req = hook(req) or req
            except Exception as e:
                logger.debug(f"[INTERCEPTOR] Request hook error: {e}")
        return req

    def process_response(self, res: ParsedResponse) -> ParsedResponse:
        for hook in self._response_hooks:
            try:
                res = hook(res) or res
            except Exception as e:
                logger.debug(f"[INTERCEPTOR] Response hook error: {e}")
        return res

    def tamper_jwt_header(self, req: ParsedRequest, new_claims: dict) -> ParsedRequest:
        """Tamper JWT payload with new claims"""
        auth = req.headers.get("Authorization", "")
        if not auth.lower().startswith("bearer "):
            return req
        try:
            token = auth[7:]
            parts = token.split(".")
            if len(parts) != 3:
                return req
            payload_raw = _b64.b64decode(parts[1] + "==")
            payload = _json.loads(payload_raw)
            payload.update(new_claims)
            new_payload = _b64.b64encode(
                _json.dumps(payload, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()
            new_token = f"{parts[0]}.{new_payload}.{parts[2]}"
            req.headers["Authorization"] = f"Bearer {new_token}"
            req.headers["X-CyberCLI-Tampered"] = "JWT-Payload"
        except Exception as e:
            logger.debug(f"[INTERCEPTOR] JWT tamper error: {e}")
        return req


# ─── session_manager.py ───────────────────────────────────────────────────────

import time as _time
from collections import defaultdict


class SessionManager:
    """Tracks HTTP sessions, cookie jars, auth tokens per host"""

    def __init__(self):
        self._sessions: dict = defaultdict(lambda: {
            "cookies": {},
            "tokens": [],
            "requests": 0,
            "first_seen": _time.time(),
            "last_seen": _time.time(),
        })

    def track(self, req: ParsedRequest):
        if not req:
            return
        host = req.headers.get("Host", "unknown")
        session = self._sessions[host]
        session["requests"] += 1
        session["last_seen"] = _time.time()

        # Extract cookies from Cookie header
        cookie_header = req.headers.get("Cookie", "")
        if cookie_header:
            for cookie in cookie_header.split(";"):
                if "=" in cookie:
                    k, v = cookie.strip().split("=", 1)
                    session["cookies"][k.strip()] = v.strip()

        # Extract auth tokens
        auth = req.headers.get("Authorization", "")
        if auth and auth not in session["tokens"]:
            session["tokens"].append(auth[:100])

    def count(self) -> int:
        return len(self._sessions)

    def get_session(self, host: str) -> dict:
        return dict(self._sessions.get(host, {}))

    def all_sessions(self) -> dict:
        return dict(self._sessions)


# ─── traffic_logger.py ────────────────────────────────────────────────────────

import os as _os
import _thread
from datetime import datetime as _dt


class TrafficLogger:
    """Logs all traffic to artifacts/proxy_logs/"""

    def __init__(self, log_dir: str = "artifacts/proxy_logs"):
        self.log_dir = log_dir
        _os.makedirs(log_dir, exist_ok=True)
        self._log_file = _os.path.join(log_dir, f"traffic_{int(_time.time())}.log")
        self._lock = _thread.allocate_lock()
        self._request_count = 0

    def log_request(self, req: Optional[ParsedRequest], addr=None):
        if not req:
            return
        self._request_count += 1
        entry = f"[{_dt.utcnow().isoformat()}] REQ #{self._request_count} {req.method} {req.url}\n"
        self._write(entry)

    def log_response(self, res: Optional[ParsedResponse]):
        if not res:
            return
        entry = f"[{_dt.utcnow().isoformat()}] RES {res.status} {res.reason}\n"
        self._write(entry)

    def _write(self, text: str):
        try:
            with self._lock:
                with open(self._log_file, "a") as f:
                    f.write(text)
        except Exception:
            pass


# ─── tls_handler.py ───────────────────────────────────────────────────────────

import ssl as _ssl
import subprocess as _sub
import tempfile as _tmp


class TLSHandler:
    """
    Handles TLS/SSL for MITM proxy.
    Generates certificates for intercepted HTTPS connections.
    """

    def __init__(self, ca_cert: str = "", ca_key: str = ""):
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self._cert_cache: dict = {}

    def get_ssl_context(self, hostname: str) -> Optional[_ssl.SSLContext]:
        """Get or generate SSL context for hostname"""
        try:
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            return ctx
        except Exception as e:
            logger.debug(f"[TLS] SSL context error: {e}")
            return None

    def create_client_context(self) -> _ssl.SSLContext:
        """SSL context for connecting to upstream targets"""
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        return ctx


# ─── crawler.py ───────────────────────────────────────────────────────────────

import aiohttp as _aiohttp
from urllib.parse import urljoin, urlparse
from typing import Set


class Crawler:
    """
    Async spider / crawler.
    Discovers all endpoints from a target URL.
    """

    def __init__(self, target: str, max_pages: int = 50, on_request: Optional[Callable] = None):
        self.target = target
        self.max_pages = max_pages
        self.on_request = on_request
        self.base_domain = urlparse(target).netloc
        self._visited: Set[str] = set()
        self._queue: _List[str] = [target]
        self._endpoints: _List[dict] = []

    async def crawl(self) -> _List[dict]:
        timeout = _aiohttp.ClientTimeout(total=10)
        connector = _aiohttp.TCPConnector(ssl=False, limit=10)

        async with _aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            while self._queue and len(self._visited) < self.max_pages:
                url = self._queue.pop(0)
                if url in self._visited:
                    continue
                self._visited.add(url)

                try:
                    async with session.get(url) as resp:
                        if self.on_request:
                            try:
                                self.on_request("GET", url, resp.status)
                            except Exception:
                                pass

                        endpoint = {
                            "url": url,
                            "method": "GET",
                            "params": dict(urlparse(url).query and
                                          {k: v for k, v in [p.split("=", 1) if "=" in p else (p, "") for p in urlparse(url).query.split("&")]} or {}),
                            "headers": {},
                            "status": resp.status,
                        }
                        self._endpoints.append(endpoint)

                        if "text/html" in resp.headers.get("Content-Type", ""):
                            body = await resp.text(errors="ignore")
                            new_urls = self._extract_links(body, url)
                            for new_url in new_urls:
                                if new_url not in self._visited:
                                    self._queue.append(new_url)

                except Exception:
                    pass

        return self._endpoints

    def _extract_links(self, html: str, base_url: str) -> _List[str]:
        links = []
        # Extract href and src attributes
        for pattern in [r'href=["\']([^"\'#>]+)["\']', r'action=["\']([^"\'#>]+)["\']']:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                href = match.group(1)
                if href.startswith(("javascript:", "mailto:", "#", "data:")):
                    continue
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)
                if parsed.netloc == self.base_domain:
                    links.append(full_url)
        return links[:20]  # Limit per page


# ─── scope_manager.py ────────────────────────────────────────────────────────

from urllib.parse import urlparse as _urlparse


class ScopeManager:
    """Manages scan scope — ensures we only test what we're authorized to test"""

    def __init__(self, target: str, extra_domains: _List[str] = None):
        self.target_domain = _urlparse(target).netloc
        self.allowed_domains = {self.target_domain}
        if extra_domains:
            self.allowed_domains.update(extra_domains)

    def in_scope(self, url: str) -> bool:
        try:
            domain = _urlparse(url).netloc
            return (domain in self.allowed_domains or
                    any(domain.endswith("." + d) for d in self.allowed_domains))
        except Exception:
            return False

    def add_domain(self, domain: str):
        self.allowed_domains.add(domain)
