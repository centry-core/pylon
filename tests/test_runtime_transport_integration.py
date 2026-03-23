#!/usr/bin/python
# coding=utf-8
# pyright: reportMissingImports=false

import socket
import time
from pathlib import Path
from types import SimpleNamespace

import arbiter

from pylon.core.tools.runtime.supervisor import RuntimeSupervisor


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _make_runtime_plan():
    return {
        "modules": {
            "transport_demo": {
                "group": "transport_group",
                "mode": "gevent",
                "restart_policy": "never",
            }
        },
        "groups": {
            "transport_group": {
                "mode": "gevent",
                "modules": ["transport_demo"],
                "restart_policy": "never",
            }
        },
    }


def _make_context(bind_pub, bind_pull):
    package_root = str(Path(__file__).resolve().parents[1])
    return SimpleNamespace(
        id="runtime_transport_test",
        settings={
            "modules": {
                "runtime": {
                    "enabled": True,
                    "worker_stdio": "inherit",
                    "worker_cwd": package_root,
                    "startup_timeout_sec": 8,
                    "startup_poll_interval_sec": 0.2,
                    "rpc_timeout_sec": 2,
                    "call_timeout_sec": 2,
                    "route_timeout_sec": 2,
                    "event_timeout_sec": 2,
                    "slot_timeout_sec": 2,
                    "api_timeout_sec": 2,
                }
            },
            "exposure": {
                "zmq": {
                    "enabled": True,
                    "bind_pub": bind_pub,
                    "bind_pull": bind_pull,
                    "topic": "events",
                }
            },
        },
        module_manager=SimpleNamespace(descriptors={}),
    )


def test_supervisor_worker_transport_ping_and_error_envelope():
    pub_port = _free_port()
    pull_port = _free_port()
    bind_pub = f"tcp://127.0.0.1:{pub_port}"
    bind_pull = f"tcp://127.0.0.1:{pull_port}"

    server = arbiter.ZeroMQServerNode(bind_pub=bind_pub, bind_pull=bind_pull)
    server.start()

    context = _make_context(bind_pub, bind_pull)
    supervisor = RuntimeSupervisor(context)
    runtime_plan = _make_runtime_plan()

    try:
        supervisor.start(runtime_plan)

        # Validate the worker is reachable through real ZeroMQ transport.
        ping_result = supervisor.rpc_node.call_with_timeout(
            "runtime_worker_transport_group_ping",
            timeout=2,
            payload={"probe": "ping"},
        )
        assert ping_result["ok"] is True
        assert ping_result["runtime_group"] == "transport_group"

        # Validate standardized error envelope for a failing route dispatch.
        call_result = supervisor.call_route(
            module_name="transport_demo",
            callable_module="plugins.transport_demo.routes.nope",
            callable_name="handler",
            module_routes=True,
            request_data={
                "method": "GET",
                "path": "/transport",
                "query_string": b"",
                "headers": {},
                "body": b"",
                "content_type": None,
                "route_kwargs": {},
            },
        )
        assert call_result["__runtime_envelope__"] is True
        assert call_result["ok"] is False
        assert "error" in call_result

    finally:
        supervisor.stop()
        time.sleep(0.2)
        server.stop()
