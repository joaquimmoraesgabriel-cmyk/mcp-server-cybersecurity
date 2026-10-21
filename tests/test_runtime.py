from __future__ import annotations

import http.client
import json
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from cyber_rag import runtime


class FakeService:
    def __init__(self):
        self.calls = []
        self.fail = False

    def dispatch(self, name, arguments):
        self.calls.append((name, arguments))
        if self.fail:
            raise RuntimeError("private-secret-marker must not escape")
        return {"status": "ok", "results": [{"operation": name}]}


@pytest.fixture
def core():
    service = FakeService()
    server = runtime._CoreHTTPServer(service, "test-query-token", "test-data-dir")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, service
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def request(core, *, method="POST", path="/call", body=None, headers=None):
    server, _ = core
    content = json.dumps(body if body is not None else {"tool": "knowledge_status", "arguments": {}}).encode()
    defaults = runtime._request_headers(method, path, content, server.server_port, "test-query-token")
    defaults.update(headers or {})
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    try:
        connection.request(method, path, body=content, headers=defaults)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), json.loads(response.read())
    finally:
        connection.close()


def test_queries_and_health_require_authentication(core):
    for path, method in (("/health", "GET"), ("/call", "POST")):
        status, _, result = request(core, path=path, method=method, headers={"Authorization": "Bearer wrong"})
        assert status == 401
        assert result["error"]["code"] == "UNAUTHORIZED"
    assert core[1].calls == []


@pytest.mark.parametrize("headers", [
    {"Host": "evil.example"}, {"Host": "localhost"},
    {"Origin": "https://evil.example"}, {"Origin": "null"},
    {"Origin": "http://127.0.0.1"},
])
def test_rejects_host_and_any_browser_origin(core, headers):
    status, response_headers, _ = request(core, headers=headers)
    assert status == 403
    assert not any(name.lower().startswith("access-control-") for name in response_headers)
    assert core[1].calls == []


def test_disallows_admin_and_unknown_endpoints(core):
    status, _, result = request(core, body={"tool": "sync", "arguments": {}})
    assert status == 400
    assert result["error"]["code"] == "INVALID_ARGUMENT"
    status, _, _ = request(core, path="/shutdown")
    assert status == 404
    assert core[1].calls == []


@pytest.mark.parametrize("body", [
    [], 42, {"tool": 42, "arguments": {}},
    {"tool": "knowledge_status", "arguments": []},
    {"tool": "knowledge_status", "arguments": {}, "admin": True},
])
def test_rejects_malformed_operation_envelopes(core, body):
    status, _, result = request(core, body=body)
    assert status == 400
    assert result["error"]["code"] == "INVALID_ARGUMENT"
    assert core[1].calls == []


def test_rejects_oversize_and_unsupported_encoding_before_reading(core):
    status, _, _ = request(core, headers={"Content-Length": str(runtime.MAX_REQUEST_BYTES + 1)})
    assert status == 413
    status, _, _ = request(core, headers={"Transfer-Encoding": "chunked"})
    assert status == 400
    status, _, _ = request(core, headers={"Content-Type": "text/plain"})
    assert status == 415
    assert core[1].calls == []


def test_rejects_duplicate_content_length(core):
    server, service = core
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    try:
        connection.putrequest("POST", "/call")
        for name, value in runtime._request_headers("POST", "/call", b"{}", server.server_port, "test-query-token").items():
            connection.putheader(name, value)
        connection.putheader("Content-Length", "2")
        connection.putheader("Content-Length", "2")
        connection.endheaders(b"{}")
        response = connection.getresponse()
        assert response.status == 400
        response.read()
        assert service.calls == []
    finally:
        connection.close()


def test_only_allowlisted_query_is_dispatched(core):
    status, headers, result = request(core)
    assert status == 200 and result["status"] == "ok"
    assert core[1].calls == [("knowledge_status", {})]
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_error_never_leaks_exception_or_credentials(core, capsys):
    core[1].fail = True
    status, _, result = request(core)
    assert status == 503
    assert result["error"]["code"] == "INDEX_UNAVAILABLE"
    captured = capsys.readouterr()
    combined = json.dumps(result) + captured.out + captured.err
    assert "private-secret-marker" not in combined
    assert "test-query-token" not in combined


def test_health_validates_process_identity(core):
    server, _ = core
    client = runtime.CoreClient(server.server_port, "test-query-token", server.instance_id, "test-data-dir")
    assert client.health()["instance_id"] == server.instance_id
    assert client.call("knowledge_status", {})["status"] == "ok"
    invalid = runtime.CoreClient(server.server_port, "test-query-token", "different-process", "test-data-dir")
    with pytest.raises(RuntimeError, match="expected local core"):
        invalid.health()
    assert client.call("execute", {})["error"]["code"] == "INVALID_ARGUMENT"


def test_authentication_does_not_send_token_and_rejects_replay(core):
    server, _ = core
    content = json.dumps({"tool": "knowledge_status", "arguments": {}}).encode()
    headers = runtime._request_headers("POST", "/call", content, server.server_port, "test-query-token")
    assert "test-query-token" not in json.dumps(headers)
    assert request(core, headers=headers)[0] == 200
    assert request(core, headers=headers)[0] == 401


def test_request_signature_binds_body(core):
    server, service = core
    headers = runtime._request_headers("POST", "/call", b"different body", server.server_port, "test-query-token")
    assert request(core, headers=headers)[0] == 401
    assert service.calls == []


def test_slow_body_has_a_deadline(core, monkeypatch):
    monkeypatch.setattr(runtime, "SOCKET_TIMEOUT", 0.05)
    server, service = core
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    headers = runtime._request_headers("POST", "/call", b"{}", server.server_port, "test-query-token")
    headers["Content-Length"] = "2"
    try:
        connection.request("POST", "/call", body=b"{", headers=headers)
        response = connection.getresponse()
        assert response.status == 504
        assert json.loads(response.read())["error"]["code"] == "TIMEOUT"
        assert service.calls == []
    finally:
        connection.close()


def test_incomplete_headers_have_a_total_deadline(core, monkeypatch):
    monkeypatch.setattr(runtime, "REQUEST_READ_TIMEOUT", 0.05)
    server, service = core
    with socket.create_connection(("127.0.0.1", server.server_port), timeout=2) as connection:
        connection.sendall(b"GET /health HTTP/1.1\r\n")
        assert connection.recv(1024) == b""
    assert service.calls == []


def test_queue_is_bounded(core):
    server, service = core
    for _ in range(runtime.MAX_CONNECTIONS):
        assert server.slots.acquire(blocking=False)
    try:
        client = runtime.CoreClient(server.server_port, "test-query-token", server.instance_id, "test-data-dir")
        result = client.call("knowledge_status", {})
        # Rejection precedes HTTP parsing; Windows can reset the socket while
        # the peer is still sending its body, before it receives the 503.
        assert result["status"] == "error"
        assert result["error"]["code"] in {"BUSY", "INDEX_UNAVAILABLE"}
        assert result["error"]["retryable"] is True
        assert service.calls == []
    finally:
        for _ in range(runtime.MAX_CONNECTIONS):
            server.slots.release()


def test_dispatch_queue_deadline(core, monkeypatch):
    monkeypatch.setattr(runtime, "QUEUE_TIMEOUT", 0.02)
    server, service = core
    server.dispatch_lock.acquire()
    try:
        status, _, result = request(core)
        assert status == 503 and result["error"]["code"] == "BUSY"
        assert service.calls == []
    finally:
        server.dispatch_lock.release()


def test_private_runtime_token_persists_and_state_has_no_secret(tmp_path):
    directory = runtime._prepare_runtime(tmp_path)
    first = runtime._token(directory)
    assert len(first) == 64
    assert runtime._token(directory) == first
    assert directory == tmp_path / "runtime"
    assert runtime._read_state(directory) is None
    (directory / "core.json").write_text('{"port": "not-a-port"}', encoding="utf-8")
    assert runtime._read_state(directory) is None


def test_invalid_token_fails_closed(tmp_path):
    directory = runtime._prepare_runtime(tmp_path)
    (directory / "query.token").write_text("invalid", encoding="ascii")
    with pytest.raises(RuntimeError, match="credentials"):
        runtime._token(directory)


def test_launcher_reuses_authenticated_core(core, tmp_path, monkeypatch):
    server, _ = core
    directory = runtime._prepare_runtime(tmp_path)
    monkeypatch.setattr(runtime, "_token", lambda _: "test-query-token")
    server.data_dir_id = runtime._data_id(tmp_path)
    (directory / "core.json").write_text(json.dumps({
        "port": server.server_port, "protocol_version": 1,
        "instance_id": server.instance_id, "data_dir_id": server.data_dir_id,
    }), encoding="utf-8")

    def no_spawn(*args, **kwargs):
        raise AssertionError("Existing healthy core must be reused")

    monkeypatch.setattr(runtime.subprocess, "Popen", no_spawn)
    clients = []
    threads = [threading.Thread(target=lambda: clients.append(runtime.ensure_core(tmp_path))) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert len(clients) == 2
    assert clients[0].instance_id == clients[1].instance_id == server.instance_id


def test_two_launchers_start_only_one_real_core(tmp_path, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", str(Path(__file__).resolve().parents[1] / "src"))
    real_popen = runtime.subprocess.Popen
    children = []

    def capture_child(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(runtime.subprocess, "Popen", capture_child)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(runtime.ensure_core, tmp_path) for _ in range(2)]
            clients = [future.result(timeout=runtime.STARTUP_TIMEOUT + 10) for future in futures]
        assert len(children) == 1
        assert clients[0].instance_id == clients[1].instance_id
        assert clients[0].health()["service"] == "cyber-rag-core"
        # Starting the transport does not download or fabricate a knowledge base.
        assert clients[1].call("knowledge_status", {})["error"]["code"] == "INDEX_UNAVAILABLE"
        state = runtime._read_state(tmp_path / "runtime")
        # Windows venv redirectors can launch the real interpreter with a
        # different PID. The authenticated instance ID is the identity proof.
        assert isinstance(state["pid"], int) and state["pid"] > 0
        assert state["instance_id"] == clients[0].instance_id
        assert "token" not in state
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=10)


@pytest.mark.parametrize("keep_alive", [False, True])
@pytest.mark.parametrize("warmup", [False, True])
def test_foreground_lifecycle_respects_keep_alive(tmp_path, monkeypatch, keep_alive, warmup):
    from cyber_rag import service as service_module

    fake = FakeService()
    prepared = []

    def prepare():
        assert runtime._read_state(tmp_path / "runtime") is None
        prepared.append(True)

    fake.warmup = prepare
    closed = threading.Event()
    fake.close = closed.set
    monkeypatch.setattr(service_module, "KnowledgeService", lambda _: fake)
    monkeypatch.setattr(runtime, "IDLE_TIMEOUT", 0.05)
    monkeypatch.setattr(runtime, "IDLE_POLL_INTERVAL", 0.02)
    original_server = runtime._CoreHTTPServer
    started = threading.Event()
    servers = []

    def capture_server(*args):
        assert prepared == ([True] if warmup else [])
        server = original_server(*args)
        servers.append(server)
        started.set()
        return server

    monkeypatch.setattr(runtime, "_CoreHTTPServer", capture_server)
    thread = threading.Thread(target=runtime.serve_core, args=(tmp_path,), kwargs={"keep_alive": keep_alive, "warmup": warmup}, daemon=True)
    thread.start()
    try:
        assert started.wait(5)
        thread.join(timeout=0.4 if keep_alive else 3)
        if keep_alive:
            assert thread.is_alive(), "Manual core must outlive the idle timeout"
            server = servers[0]
            client = runtime.CoreClient(server.server_port, server.query_token, server.instance_id, server.data_dir_id)
            assert client.call("knowledge_status", {})["status"] == "ok"
            server.shutdown()
            thread.join(timeout=3)
        assert not thread.is_alive()
        assert closed.is_set()
        assert runtime._read_state(tmp_path / "runtime") is None
    finally:
        if thread.is_alive() and servers:
            servers[0].shutdown()
            thread.join(timeout=3)


def test_failed_warmup_never_publishes_core_and_releases_resources(tmp_path, monkeypatch):
    from cyber_rag import service as service_module

    fake = FakeService()
    closed = threading.Event()
    fake.close = closed.set

    def fail_warmup():
        raise RuntimeError("Model unavailable")

    fake.warmup = fail_warmup
    monkeypatch.setattr(service_module, "KnowledgeService", lambda _: fake)
    with pytest.raises(RuntimeError, match="Model unavailable"):
        runtime.serve_core(tmp_path, warmup=True)
    assert closed.is_set()
    assert runtime._read_state(tmp_path / "runtime") is None
    with runtime.FileLock(str(tmp_path / "runtime" / "core.lock"), timeout=0):
        pass
