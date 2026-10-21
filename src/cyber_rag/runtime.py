"""Private loopback transport shared by local MCP adapters.

The HTTP listener is an implementation detail, not a remote MCP endpoint. Only
explicit knowledge and derived-memory operations are reachable. In-flight inference is
not forcibly cancelled: socket and queue deadlines bound waiting, not compute.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from filelock import FileLock
from filelock import Timeout as LockTimeout

from .research import EXTENDED_TOOLS, TOOL_CONTRACT

TOOLS = frozenset(
    {
        "knowledge_search",
        "knowledge_get_entity",
        "knowledge_get_document",
        "knowledge_get_related",
        "knowledge_status",
    }
) | frozenset(EXTENDED_TOOLS)
PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_CONNECTIONS = 8
SOCKET_TIMEOUT = 15.0
REQUEST_READ_TIMEOUT = 20.0
QUEUE_TIMEOUT = 10.0
CLIENT_TIMEOUT = 120.0
STARTUP_TIMEOUT = 45.0
IDLE_TIMEOUT = 15 * 60.0
IDLE_POLL_INTERVAL = 5.0
AUTH_WINDOW = 60.0


def _finish_rejected_socket(connection: socket.socket) -> None:
    """Let a small in-flight request finish without resetting our error reply.

    Windows may discard the response if we close with unread request bytes.
    Draining is bounded in both time and bytes; rejected data is never parsed.
    """
    deadline = time.monotonic() + 0.1
    remaining = MAX_REQUEST_BYTES
    try:
        connection.shutdown(socket.SHUT_WR)
        while remaining > 0:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                break
            connection.settimeout(timeout)
            chunk = connection.recv(min(8192, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
    except OSError:
        pass


def _error(code: str, message: str, retryable: bool = False) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "request_id": str(uuid.uuid4()),
        "status": "error",
        "error": {"code": code, "message": message, "retryable": retryable},
    }


def _signature(token: str, *parts: str) -> str:
    return hmac.new(token.encode("ascii"), "\n".join(parts).encode("utf-8"), hashlib.sha256).hexdigest()


def _request_headers(method: str, path: str, body: bytes, port: int, token: str) -> dict[str, str]:
    nonce = secrets.token_hex(32)
    timestamp = str(int(time.time()))
    digest = hashlib.sha256(body).hexdigest()
    return {
        "Authorization": "HMAC " + _signature(token, method, path, str(port), nonce, timestamp, digest),
        "X-Request-Nonce": nonce,
        "X-Request-Time": timestamp,
        "X-Body-SHA256": digest,
        "Content-Type": "application/json",
        "Connection": "close",
    }


def _windows_private_directory(path: Path) -> None:
    """Set a protected DACL for the current Windows user and SYSTEM only."""
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    handle = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(handle)):
        raise RuntimeError("Cannot secure the local runtime directory.")
    sid_string = wintypes.LPWSTR()
    descriptor = ctypes.c_void_p()
    try:
        size = wintypes.DWORD()
        advapi.GetTokenInformation(handle, 1, None, 0, ctypes.byref(size))
        token = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(handle, 1, token, size, ctypes.byref(size)):
            raise RuntimeError("Cannot secure the local runtime directory.")
        sid = ctypes.cast(token, ctypes.POINTER(ctypes.c_void_p)).contents.value
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_string)):
            raise RuntimeError("Cannot secure the local runtime directory.")
        sddl = f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid_string.value})"
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None
        ):
            raise RuntimeError("Cannot secure the local runtime directory.")
        # DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION.
        if not advapi.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise RuntimeError("Cannot secure the local runtime directory.")
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)
        if sid_string:
            kernel.LocalFree(ctypes.cast(sid_string, ctypes.c_void_p))
        kernel.CloseHandle(handle)


def _is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _prepare_runtime(data_dir: Path) -> Path:
    runtime_dir = data_dir.resolve() / "runtime"
    if _is_link(runtime_dir):
        raise RuntimeError("The runtime directory cannot be a link.")
    runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "nt":
        _windows_private_directory(runtime_dir)
    else:
        if runtime_dir.stat().st_uid != os.getuid():
            raise RuntimeError("The runtime directory must belong to the current user.")
        runtime_dir.chmod(0o700)
    return runtime_dir


def _token(runtime_dir: Path) -> str:
    with FileLock(str(runtime_dir / "token.lock"), timeout=5):
        return _read_or_create_token(runtime_dir)


def _read_or_create_token(runtime_dir: Path) -> str:
    path = runtime_dir / "query.token"
    if _is_link(path):
        raise RuntimeError("The local token cannot be a link.")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if path.stat().st_size > 256:
            raise RuntimeError("Invalid local runtime credentials.") from None
        if os.name == "nt":
            _windows_private_directory(path)
        else:
            path.chmod(0o600)
        token = path.read_text(encoding="ascii").strip()
    else:
        token = secrets.token_urlsafe(48)
        with os.fdopen(fd, "w", encoding="ascii") as output:
            output.write(token)
            output.flush()
            os.fsync(output.fileno())
    if not re.fullmatch(r"[A-Za-z0-9_-]{64}", token):
        raise RuntimeError("Invalid local runtime credentials.")
    if os.name != "nt":
        path.chmod(0o600)
    return token


def _data_id(data_dir: Path) -> str:
    return hashlib.sha256(os.path.normcase(str(data_dir.resolve())).encode("utf-8")).hexdigest()


def _read_state(runtime_dir: Path) -> dict[str, Any] | None:
    path = runtime_dir / "core.json"
    try:
        if _is_link(path) or path.stat().st_size > 4096:
            return None
        state = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(state, dict) or type(state.get("port")) is not int:
            return None
        if not 1 <= state["port"] <= 65535 or state.get("protocol_version") != PROTOCOL_VERSION:
            return None
        if not isinstance(state.get("instance_id"), str) or not isinstance(state.get("data_dir_id"), str):
            return None
        return state
    except (OSError, ValueError, UnicodeError):
        return None


class CoreClient:
    """Client for a fixed authenticated loopback endpoint; it never uses proxies."""

    def __init__(
        self, port: int, token: str, instance_id: str, data_dir_id: str, *, timeout: float = CLIENT_TIMEOUT
    ):
        self.port = port
        self._token = token
        self.instance_id = instance_id
        self.data_dir_id = data_dir_id
        self.timeout = timeout

    def _request(
        self, method: str, path: str, payload: dict[str, Any] | None = None, *, timeout: float | None = None
    ) -> dict[str, Any]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout or self.timeout)
        try:
            body = (
                json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
                if payload is not None
                else None
            )
            if body is not None and len(body) > MAX_REQUEST_BYTES:
                return _error("INVALID_ARGUMENT", "Request exceeds the local transport limit.")
            headers = _request_headers(method, path, body or b"", self.port, self._token)
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return _error("INDEX_UNAVAILABLE", "The local core returned an invalid response.", True)
            expected = _signature(
                self._token, headers["X-Request-Nonce"], str(response.status), hashlib.sha256(raw).hexdigest()
            )
            signature = response.getheader("X-Response-Signature", "")
            if not hmac.compare_digest(signature, expected):
                # Busy sockets are rejected before parsing headers. Treat that as
                # busy without accepting any unauthenticated response data.
                if response.status == 503:
                    return _error("BUSY", "The local core could not accept this request.", True)
                return _error(
                    "INDEX_UNAVAILABLE", "The local core response could not be authenticated.", True
                )
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise TypeError("Invalid response")
            if response.status not in {200, 400, 401, 403, 404, 405, 413, 415, 429, 503, 504}:
                return _error("INDEX_UNAVAILABLE", "The local core is unavailable.", True)
            return result
        except TimeoutError:
            return _error("TIMEOUT", "The local core did not respond before the deadline.", True)
        except (OSError, http.client.HTTPException, ValueError, TypeError, RecursionError):
            return _error("INDEX_UNAVAILABLE", "The local core is unavailable.", True)
        finally:
            connection.close()

    def health(self) -> dict[str, Any]:
        result = self._request("GET", "/health", timeout=2.0)
        if (
            result.get("service") != "cyber-rag-core"
            or result.get("protocol_version") != PROTOCOL_VERSION
            or result.get("instance_id") != self.instance_id
            or result.get("data_dir_id") != self.data_dir_id
        ):
            raise RuntimeError("The expected local core is unavailable.")
        return result

    def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool not in TOOLS or not isinstance(arguments, dict):
            return _error("INVALID_ARGUMENT", "Unsupported knowledge operation or arguments.")
        if tool in EXTENDED_TOOLS:
            try:
                if self.health().get("tool_contract", 1) < TOOL_CONTRACT:
                    return _error(
                        "CORE_UPGRADE_REQUIRED",
                        "Reinicie o núcleo local para habilitar pesquisa sob demanda e memória.",
                        False,
                    )
            except RuntimeError:
                return _error("INDEX_UNAVAILABLE", "The expected local core is unavailable.", True)
        return self._request("POST", "/call", {"tool": tool, "arguments": arguments})


class _CoreHTTPServer(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True
    request_queue_size = MAX_CONNECTIONS
    allow_reuse_address = False

    def __init__(self, service: Any, token: str, data_dir_id: str):
        self.service = service
        self.query_token = token
        self.instance_id = str(uuid.uuid4())
        self.data_dir_id = data_dir_id
        self.dispatch_lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.last_activity = time.monotonic()
        self.active_requests = 0
        self.activity_lock = threading.Lock()
        self.nonces: dict[str, float] = {}
        self.auth_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _CoreHandler)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(SOCKET_TIMEOUT)
        return request, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(0.1)
                body = json.dumps(_error("BUSY", "The local request queue is full.", True)).encode()
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\n\r\n"
                    + body
                )
            except OSError:
                pass
            finally:
                _finish_rejected_socket(request)
                self.shutdown_request(request)
            return
        with self.activity_lock:
            self.active_requests += 1
            self.last_activity = time.monotonic()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._release_slot()
            raise

    def _release_slot(self):
        with self.activity_lock:
            self.active_requests -= 1
            self.last_activity = time.monotonic()
        self.slots.release()

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release_slot()

    def handle_error(self, request, client_address):
        # Never print request bodies, credentials or tracebacks to adapter stdout.
        pass


class _CoreHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "cyber-rag"
    sys_version = ""

    def setup(self):
        super().setup()

        def expire_read():
            # Socket inactivity limits alone permit one-byte-at-a-time requests.
            # Bound total header/body reading even before authentication succeeds.
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        self.read_deadline = threading.Timer(REQUEST_READ_TIMEOUT, expire_read)
        self.read_deadline.daemon = True
        self.read_deadline.start()

    def finish(self):
        self.read_deadline.cancel()
        try:
            super().finish()
        finally:
            if getattr(self, "rejected", False):
                _finish_rejected_socket(self.connection)

    def log_message(self, format, *args):
        pass

    def _send(self, status: int, payload: dict[str, Any]):
        self.close_connection = True
        self.rejected = status >= 400
        try:
            data = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
            if len(data) > MAX_RESPONSE_BYTES:
                status = 503
                data = json.dumps(
                    _error("INDEX_UNAVAILABLE", "Response exceeds the local transport limit.")
                ).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            nonce = getattr(self, "headers", {}).get("X-Request-Nonce", "")
            if re.fullmatch(r"[a-f0-9]{64}", nonce):
                self.send_header(
                    "X-Response-Signature",
                    _signature(self.server.query_token, nonce, str(status), hashlib.sha256(data).hexdigest()),
                )
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
        except (OSError, ValueError, TypeError):
            pass

    def send_error(self, code, message=None, explain=None):
        self._send(code, _error("INVALID_ARGUMENT", "Invalid local transport request."))

    def _authorize(self) -> bool:
        expected_host = f"127.0.0.1:{self.server.server_port}"
        if self.headers.get_all("Host", []) != [expected_host] or self.headers.get_all("Origin", []):
            self._send(403, _error("FORBIDDEN", "This endpoint only accepts local application requests."))
            return False
        if self.headers.get_all("Transfer-Encoding", []):
            self._send(400, _error("INVALID_ARGUMENT", "Transfer encoding is unsupported."))
            return False
        names = ("Authorization", "X-Request-Nonce", "X-Request-Time", "X-Body-SHA256")
        values = {name: self.headers.get_all(name, []) for name in names}
        if any(len(value) != 1 for value in values.values()):
            self._send(401, _error("UNAUTHORIZED", "Local authentication is required."))
            return False
        authorization, nonce, timestamp, digest = [values[name][0] for name in names]
        valid_shape = (
            re.fullmatch(r"HMAC [a-f0-9]{64}", authorization)
            and re.fullmatch(r"[a-f0-9]{64}", nonce)
            and re.fullmatch(r"[0-9]{10,12}", timestamp)
            and re.fullmatch(r"[a-f0-9]{64}", digest)
        )
        expected = "HMAC " + _signature(
            self.server.query_token,
            self.command,
            self.path,
            str(self.server.server_port),
            nonce,
            timestamp,
            digest,
        )
        if (
            not valid_shape
            or abs(time.time() - int(timestamp)) > AUTH_WINDOW
            or not hmac.compare_digest(authorization.encode("utf-8"), expected.encode("ascii"))
        ):
            self._send(401, _error("UNAUTHORIZED", "Local authentication is required."))
            return False
        with self.server.auth_lock:
            now = time.monotonic()
            self.server.nonces = {
                value: expiry for value, expiry in self.server.nonces.items() if expiry > now
            }
            if nonce in self.server.nonces:
                self._send(401, _error("UNAUTHORIZED", "A fresh local authentication proof is required."))
                return False
            if len(self.server.nonces) >= 4096:
                self._send(429, _error("BUSY", "Local authentication rate limit exceeded.", True))
                return False
            self.server.nonces[nonce] = now + 2 * AUTH_WINDOW
        self.body_digest = digest
        return True

    def do_GET(self):
        if not self._authorize():
            return
        self.read_deadline.cancel()
        if self.path != "/health":
            self._send(404, _error("NOT_FOUND", "Unknown local endpoint."))
            return
        self._send(
            200,
            {
                "service": "cyber-rag-core",
                "protocol_version": PROTOCOL_VERSION,
                "tool_contract": TOOL_CONTRACT,
                "instance_id": self.server.instance_id,
                "data_dir_id": self.server.data_dir_id,
            },
        )

    def do_POST(self):
        if not self._authorize():
            return
        if self.path != "/call":
            self._send(404, _error("NOT_FOUND", "Unknown local endpoint."))
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,8}", lengths[0]):
            self._send(400, _error("INVALID_ARGUMENT", "One valid content length is required."))
            return
        length = int(lengths[0])
        if not 0 < length <= MAX_REQUEST_BYTES:
            self._send(413, _error("INVALID_ARGUMENT", "Request exceeds the local transport limit."))
            return
        content_types = self.headers.get_all("Content-Type", [])
        if len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() != "application/json":
            self._send(415, _error("INVALID_ARGUMENT", "JSON content type is required."))
            return
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("Incomplete body")
            if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), self.body_digest):
                self._send(401, _error("UNAUTHORIZED", "Request body authentication failed."))
                return
            payload = json.loads(
                raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Non-finite number"))
            )
            if not isinstance(payload, dict) or set(payload) != {"tool", "arguments"}:
                raise ValueError("Invalid payload")
            if (
                not isinstance(payload["tool"], str)
                or payload["tool"] not in TOOLS
                or not isinstance(payload["arguments"], dict)
            ):
                raise ValueError("Invalid operation")
        except (ValueError, UnicodeError, RecursionError):
            self._send(400, _error("INVALID_ARGUMENT", "Invalid knowledge operation or JSON arguments."))
            return
        except (OSError, TimeoutError):
            self._send(504, _error("TIMEOUT", "Request body deadline exceeded.", True))
            return
        self.read_deadline.cancel()
        # Remote fetches and memory have a separate fail-fast lock in ResearchService.
        # They must never occupy the snapshot queue while waiting for the network.
        snapshot_operation = payload["tool"] not in EXTENDED_TOOLS
        if snapshot_operation and not self.server.dispatch_lock.acquire(timeout=QUEUE_TIMEOUT):
            self._send(503, _error("BUSY", "The local query queue deadline was exceeded.", True))
            return
        try:
            result = self.server.service.dispatch(payload["tool"], payload["arguments"])
            if not isinstance(result, dict):
                raise TypeError("Invalid service result")
            self._send(200, result)
        except Exception:  # noqa: BLE001 - the transport boundary must never expose internal exceptions.
            self._send(503, _error("INDEX_UNAVAILABLE", "The knowledge service is unavailable.", True))
        finally:
            if snapshot_operation:
                self.server.dispatch_lock.release()

    def do_OPTIONS(self):
        self._send(405, _error("INVALID_ARGUMENT", "Browser access is unsupported."))


def _client_for_state(runtime_dir: Path, token: str, data_dir: Path) -> CoreClient | None:
    state = _read_state(runtime_dir)
    if state is None or state["data_dir_id"] != _data_id(data_dir):
        return None
    client = CoreClient(state["port"], token, state["instance_id"], state["data_dir_id"])
    try:
        client.health()
        return client
    except RuntimeError:
        return None


def ensure_core(data_dir: Path) -> CoreClient:
    """Reuse an authenticated core, or start exactly one under the launcher lock."""
    data_dir = data_dir.resolve()
    runtime_dir = _prepare_runtime(data_dir)
    try:
        with FileLock(str(runtime_dir / "launcher.lock"), timeout=STARTUP_TIMEOUT + 5):
            token = _token(runtime_dir)
            existing = _client_for_state(runtime_dir, token, data_dir)
            if existing is not None:
                return existing
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            process = subprocess.Popen(
                [sys.executable, "-m", "cyber_rag", "core", "--data-dir", str(data_dir)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=flags,
                start_new_session=os.name != "nt",
                close_fds=True,
            )
            deadline = time.monotonic() + STARTUP_TIMEOUT
            while time.monotonic() < deadline:
                client = _client_for_state(runtime_dir, token, data_dir)
                if client is not None:
                    return client
                if process.poll() is not None:
                    try:
                        # A foreground core may have won the process lock while
                        # this launcher was starting its child. Wait for its state.
                        with FileLock(str(runtime_dir / "core.lock"), timeout=0):
                            raise RuntimeError(
                                "The local core could not start; run the core command for diagnostics."
                            )
                    except LockTimeout:
                        pass
                time.sleep(0.1)
            if process.poll() is None:
                process.terminate()  # Only our own child, never a PID from a state file.
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            raise RuntimeError("The local core did not start before the deadline.")
    except LockTimeout:
        raise RuntimeError("Another local core launcher is busy; retry shortly.") from None


def serve_core(data_dir: Path, *, keep_alive: bool = False, warmup: bool = False) -> None:
    """Run the singleton read-only core; administration remains outside HTTP."""
    from cyber_rag.service import KnowledgeService

    data_dir = data_dir.resolve()
    runtime_dir = _prepare_runtime(data_dir)
    process_lock = FileLock(str(runtime_dir / "core.lock"), timeout=0)
    try:
        process_lock.acquire()
    except LockTimeout:
        raise RuntimeError("A knowledge core already owns this data directory.") from None
    service = None
    server = None
    stop_event = threading.Event()
    previous_handlers = {}
    try:
        token = _token(runtime_dir)
        service = KnowledgeService(data_dir)
        if warmup and (data_dir / "active.json").exists():
            print(
                "[cyber-rag] Preparando modelo e indice local. Aguarde antes de conectar os clientes...",
                file=sys.stderr,
                flush=True,
            )
            service.warmup()
        server = _CoreHTTPServer(service, token, _data_id(data_dir))
        state = {
            "protocol_version": PROTOCOL_VERSION,
            "pid": os.getpid(),
            "port": server.server_port,
            "instance_id": server.instance_id,
            "data_dir_id": server.data_dir_id,
        }
        temporary = runtime_dir / f"core-{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("x", encoding="utf-8") as output:
                json.dump(state, output)
                output.flush()
                os.fsync(output.fileno())
            if os.name != "nt":
                temporary.chmod(0o600)
            os.replace(temporary, runtime_dir / "core.json")
        finally:
            temporary.unlink(missing_ok=True)

        def stop_on_signal(signum, frame):
            threading.Thread(target=server.shutdown, daemon=True).start()

        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[signum] = signal.signal(signum, stop_on_signal)

        def idle_monitor():
            while not stop_event.wait(IDLE_POLL_INTERVAL):
                with server.activity_lock:
                    idle = (
                        server.active_requests == 0
                        and time.monotonic() - server.last_activity >= IDLE_TIMEOUT
                    )
                if idle:
                    server.shutdown()
                    return

        if not keep_alive:
            threading.Thread(target=idle_monitor, daemon=True, name="cyber-rag-idle").start()
        if warmup:
            print(
                "[cyber-rag] Pronto. Modelo e indice preparados para consultas.", file=sys.stderr, flush=True
            )
        server.serve_forever(poll_interval=0.2)
    finally:
        stop_event.set()
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        if server is not None:
            server.server_close()
            state = _read_state(runtime_dir)
            if state and state["instance_id"] == server.instance_id:
                (runtime_dir / "core.json").unlink(missing_ok=True)
        if service is not None:
            service.close()
        process_lock.release()
