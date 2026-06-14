"""
╔══════════════════════════════════════════════════════════════════╗
║          CyberCLI PROXY CORE — MITM Security Proxy               ║
║          AI-Powered · Better than OWASP ZAP · Less FP            ║
╚══════════════════════════════════════════════════════════════════╝
"""

import asyncio
import ssl
import socket
import threading
import logging
import time
from typing import Optional, Callable, Dict, List
from dataclasses import dataclass, field
from datetime import datetime

from cybercli.core.proxy.interceptor import Interceptor
from cybercli.core.proxy.request_parser import RequestParser
from cybercli.core.proxy.response_parser import ResponseParser
from cybercli.core.proxy.session_manager import SessionManager
from cybercli.core.proxy.passive_scan import PassiveScanner
from cybercli.core.proxy.traffic_logger import TrafficLogger
from cybercli.core.proxy.tls_handler import TLSHandler

logger = logging.getLogger("cybercli.proxy")


@dataclass
class ProxyConfig:
    host: str = "127.0.0.1"
    port: int = 8888
    target: str = ""
    intercept_mode: bool = False
    ssl_strip: bool = False
    upstream_proxy: Optional[str] = None
    timeout: int = 30
    max_connections: int = 100
    scope: List[str] = field(default_factory=list)
    verbose: bool = True


class CyberProxy:
    """
    Core MITM Proxy Engine.
    Intercepts HTTP/HTTPS, supports WebSocket, JWT tamper,
    session tracking, passive scanning, and full traffic logging.
    Designed to integrate cleanly — failure here does NOT break other modules.
    """

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.interceptor = Interceptor()
        self.req_parser = RequestParser()
        self.res_parser = ResponseParser()
        self.session_mgr = SessionManager()
        self.passive_scanner = PassiveScanner()
        self.traffic_logger = TrafficLogger()
        self.tls_handler = TLSHandler()
        self._server = None
        self._running = False
        self._request_count = 0
        self._findings = []
        self._callbacks: List[Callable] = []

    def add_finding_callback(self, cb: Callable):
        """Register callback for when passive scan finds something"""
        self._callbacks.append(cb)

    def _notify(self, finding: dict):
        self._findings.append(finding)
        for cb in self._callbacks:
            try:
                cb(finding)
            except Exception:
                pass

    def start(self) -> bool:
        """Start proxy — returns False on failure, does not raise"""
        try:
            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server.bind((self.config.host, self.config.port))
            self._server.listen(self.config.max_connections)
            self._running = True
            thread = threading.Thread(target=self._accept_loop, daemon=True)
            thread.start()
            logger.info(f"[PROXY] Listening on {self.config.host}:{self.config.port}")
            return True
        except Exception as e:
            logger.error(f"[PROXY] Failed to start: {e}")
            return False

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass

    def _accept_loop(self):
        while self._running:
            try:
                self._server.settimeout(1.0)
                conn, addr = self._server.accept()
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(conn, addr),
                    daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.debug(f"[PROXY] Accept error: {e}")

    def _handle_connection(self, conn: socket.socket, addr):
        try:
            data = conn.recv(65535)
            if not data:
                return

            self._request_count += 1
            req = self.req_parser.parse(data)
            if not req:
                return

            # Log traffic
            self.traffic_logger.log_request(req, addr)

            # Passive scan on request
            req_findings = self.passive_scanner.scan_request(req)
            for f in req_findings:
                self._notify(f)

            # Intercept/modify if needed
            req = self.interceptor.process_request(req)

            # Session tracking
            self.session_mgr.track(req)

            # Forward request
            response = self._forward_request(req)
            if response:
                # Passive scan on response
                res_findings = self.passive_scanner.scan_response(response, req)
                for f in res_findings:
                    self._notify(f)

                self.traffic_logger.log_response(response)
                conn.sendall(response.raw)

        except Exception as e:
            logger.debug(f"[PROXY] Connection error: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _forward_request(self, req):
        """Forward request to target, return response object"""
        try:
            import urllib.request
            import urllib.error

            url = req.url
            headers = dict(req.headers)

            # Strip proxy-specific headers
            for h in ["Proxy-Connection", "Proxy-Authorization"]:
                headers.pop(h, None)

            r = urllib.request.Request(
                url,
                data=req.body if req.method in ("POST", "PUT", "PATCH") else None,
                headers=headers,
                method=req.method
            )

            with urllib.request.urlopen(r, timeout=self.config.timeout) as resp:
                return self.res_parser.from_urllib(resp)

        except Exception as e:
            logger.debug(f"[PROXY] Forward error: {e}")
            return None

    def get_findings(self) -> List[dict]:
        return list(self._findings)

    def get_stats(self) -> dict:
        return {
            "requests": self._request_count,
            "findings": len(self._findings),
            "sessions": self.session_mgr.count(),
            "running": self._running,
        }
