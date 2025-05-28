from __future__ import annotations

import contextlib
import json
import logging
import socket
import ssl
import threading
from typing import TYPE_CHECKING

from app.protocols.handlers import handle_message

if TYPE_CHECKING:
    from flask import Flask

logger = logging.getLogger(__name__)


class SecureTCPServer:
    def __init__(
        self,
        app: Flask,
        host: str = "0.0.0.0",  # noqa: S104
        port: int = 6174,
        cert_file: str = "server.crt",
        key_file: str = "server.key",
    ) -> None:
        self.app = app
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.server_socket: socket.socket | None = None
        self.running = False
        self.ssl_context = None

        try:
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
            logger.info("TLS certificates loaded successfully")
        except ssl.SSLError:
            logger.exception("Failed to load TLS certificates")
        except FileNotFoundError:
            logger.exception("Certificate files not found")

    def start(self) -> None:
        """Start the TCP server in a separate thread"""
        server_thread = threading.Thread(target=self.run_server)
        server_thread.daemon = True
        server_thread.start()
        logger.info("TCP Server started on %s:%d", self.host, self.port)

    def run_server(self) -> None:
        """Run the TCP server with TLS encryption"""
        if not self.ssl_context:
            logger.error("Cannot start TCP server: TLS context not initialized")
            return

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True

            while self.running:
                self.accept_and_handle_client()
        except Exception:
            logger.exception("TCP server error")
        finally:
            self.stop()

    def accept_and_handle_client(self) -> None:
        client_socket = None
        try:
            if self.server_socket is None:
                logger.error("Server socket is not initialized")
                return
            client_socket, client_address = self.server_socket.accept()
            logger.debug("Accepted connection from %s", client_address)

            if self.is_http_request(client_socket, client_address):
                return

            if self.ssl_context is None:
                logger.error("SSL context is not initialized, closing client socket")
                client_socket.close()
                return

            secure_client_socket = self.ssl_context.wrap_socket(
                client_socket,
                server_side=True,
            )

            client_thread = threading.Thread(
                target=self._handle_client,
                args=(secure_client_socket, client_address),
            )
            client_thread.daemon = True
            client_thread.start()
        except ssl.SSLError as e:
            self.handle_ssl_error(e, client_socket, locals().get("client_address", "unknown"))
        except OSError:
            if not self.running:
                return
            logger.exception("Socket error during accept")
            if client_socket:
                with contextlib.suppress(Exception):
                    client_socket.close()

    def is_http_request(self, client_socket: socket.socket, client_address: tuple[str, int]) -> bool:
        client_socket.setblocking(False)  # noqa: FBT003
        try:
            peek_data = client_socket.recv(4, socket.MSG_PEEK)
            if peek_data.startswith((b"GET ", b"POST", b"HTTP")):
                logger.warning("HTTP request detected on SSL port from %s - rejecting", client_address)
                error_msg = (
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 50\r\n\r\n"
                    b"Error: This is an SSL/TLS port, not an HTTP port."
                )
                client_socket.sendall(error_msg)
                client_socket.close()
                return True
        except (BlockingIOError, OSError) as e:
            logger.debug("Non-blocking socket error while peeking for HTTP request: %s", e)
        finally:
            client_socket.setblocking(True)  # noqa: FBT003
        return False

    def handle_ssl_error(
        self,
        e: Exception,
        client_socket: socket.socket | None,
        client_address: tuple[str, int],
    ) -> None:
        if "HTTP_REQUEST" in str(e):
            logger.warning(
                "HTTP request received on SSL port from %s - connection rejected",
                client_address,
            )
            if client_socket:
                with contextlib.suppress(Exception):
                    error_msg = (
                        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 50\r\n\r\n"
                        b"Error: This is an SSL/TLS port, not an HTTP port."
                    )
                    client_socket.sendall(error_msg)
                    client_socket.close()
        else:
            logger.exception("SSL Error during connection")
            if client_socket:
                with contextlib.suppress(Exception):
                    client_socket.close()

    def _handle_client(self, client_socket: ssl.SSLSocket, client_address: tuple[str, int]) -> None:
        """Handle communication with a connected client"""
        try:
            data = b""
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                data += chunk

                if b"\n" in data:
                    break

            if data:
                try:
                    message = json.loads(data.decode("utf-8"))

                    with self.app.app_context():
                        response = handle_message(message)

                    response_data = json.dumps(response).encode("utf-8") + b"\n"
                    client_socket.sendall(response_data)
                except json.JSONDecodeError:
                    error_msg = {"status": "error", "message": "Invalid JSON format"}
                    client_socket.sendall(json.dumps(error_msg).encode("utf-8") + b"\n")

        except (ValueError, TypeError) as e:
            error_response = {"status": "error", "message": str(e)}
            with contextlib.suppress(OSError):
                client_socket.sendall(json.dumps(error_response).encode("utf-8") + b"\n")
            logger.exception("Error processing message from %s", client_address)
        except OSError:
            logger.exception("Socket error with client %s", client_address)
        finally:
            with contextlib.suppress(Exception):
                client_socket.close()

    def stop(self) -> None:
        """Stop the TCP server"""
        self.running = False
        if self.server_socket:
            with contextlib.suppress(Exception):
                self.server_socket.close()

        logger.info("TCP Server stopped")
