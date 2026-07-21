"""Process lifecycle for the local SMTP gateway simulation."""

from __future__ import annotations

import ipaddress
import threading

from .config import GatewayConfig
from .logging import log_event
from .processor import GatewayProcessor
from .smtp import build_smtp_controller
from .web import GatewayHTTPServer, build_admin_server, build_health_server


class GatewayApplication:
    def __init__(self, config: GatewayConfig):
        self.config = config
        self.processor = GatewayProcessor(config)
        self.smtp_controller = build_smtp_controller(config, self.processor)
        self.health_server: GatewayHTTPServer | None = None
        self.admin_server: GatewayHTTPServer | None = None
        self._threads: list[threading.Thread] = []
        self.smtp_running = False

    def start(self) -> None:
        self._validate_admin_bind()
        self.smtp_controller.start()
        self.smtp_running = True
        self.health_server = build_health_server(
            self.config.health_host,
            self.config.health_port,
            self.processor,
            lambda: self.smtp_running,
        )
        self.admin_server = build_admin_server(
            self.config.web_ui_host,
            self.config.web_ui_port,
            self.processor,
        )
        self._start_http_thread(self.health_server, "gateway-health")
        self._start_http_thread(self.admin_server, "gateway-admin")
        log_event(
            self.processor.logger,
            "gateway_started",
            smtp=f"{self.config.smtp_listen_host}:{self.config.smtp_listen_port}",
            health=f"{self.config.health_host}:{self.config.health_port}",
            web_ui=f"{self.config.web_ui_host}:{self.config.web_ui_port}",
            simulation=self.config.simulate_analyzer,
        )

    def wait(self) -> None:
        if self.admin_server is None:
            raise RuntimeError("Gateway has not been started")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            return

    def stop(self) -> None:
        self.smtp_running = False
        try:
            self.smtp_controller.stop()
        except RuntimeError:
            pass
        for server in (self.health_server, self.admin_server):
            if server is not None:
                server.shutdown()
                server.server_close()
        for thread in self._threads:
            thread.join(timeout=2)
        self.processor.close()

    def _start_http_thread(self, server: GatewayHTTPServer, name: str) -> None:
        thread = threading.Thread(target=server.serve_forever, name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

    def _validate_admin_bind(self) -> None:
        try:
            address = ipaddress.ip_address(self.config.web_ui_host)
        except ValueError:
            if self.config.web_ui_host.lower() != "localhost":
                raise ValueError("WEB_UI_HOST must resolve to a loopback address") from None
            return
        if not address.is_loopback and not _running_in_container():
            raise ValueError(
                "The administration UI only permits a non-loopback bind inside a container"
            )


def _running_in_container() -> bool:
    from pathlib import Path

    return Path("/.dockerenv").exists()


def main() -> None:
    config = GatewayConfig.from_env()
    application = GatewayApplication(config)
    try:
        application.start()
        application.wait()
    finally:
        application.stop()


if __name__ == "__main__":
    main()
