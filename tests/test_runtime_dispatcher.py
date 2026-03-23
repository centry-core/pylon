#!/usr/bin/python
# coding=utf-8
# pyright: reportMissingImports=false

import sys
import types
from types import SimpleNamespace


def _install_centry_stubs():
    if "centry_logging" in sys.modules:
        return
    log_stub = SimpleNamespace(
        exception=lambda *args, **kwargs: None,
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
        debug=lambda *args, **kwargs: None,
    )
    centry_logging = types.ModuleType("centry_logging")
    centry_logging.log = log_stub
    tools_debug = types.ModuleType("centry_logging.tools.debug")
    filters_string = types.ModuleType("centry_logging.filters.string")
    tools_debug.DebugLogStream = object
    filters_string.StringFilter = object
    sys.modules["centry_logging"] = centry_logging
    sys.modules["centry_logging.tools"] = types.ModuleType("centry_logging.tools")
    sys.modules["centry_logging.tools.debug"] = tools_debug
    sys.modules["centry_logging.filters"] = types.ModuleType("centry_logging.filters")
    sys.modules["centry_logging.filters.string"] = filters_string


def _install_web_stubs():
    if "flask" not in sys.modules:
        flask_mod = types.ModuleType("flask")
        flask_mod.request = SimpleNamespace(
            method="GET",
            path="/",
            query_string=b"",
            headers={},
            get_data=lambda: b"",
            content_type=None,
        )
        flask_mod.make_response = lambda payload: payload
        sys.modules["flask"] = flask_mod
    if "flask_restful" not in sys.modules:
        flask_restful_mod = types.ModuleType("flask_restful")
        flask_restful_mod.Resource = object
        sys.modules["flask_restful"] = flask_restful_mod


def _install_arbiter_stubs():
    if "arbiter" in sys.modules:
        return
    arbiter_mod = types.ModuleType("arbiter")
    arbiter_mod.ZeroMQEventNode = object
    arbiter_mod.RpcNode = object
    arbiter_mod.MockEventNode = object
    sys.modules["arbiter"] = arbiter_mod


_install_centry_stubs()
_install_web_stubs()
_install_arbiter_stubs()

from pylon.core.tools.runtime.dispatcher import RuntimeDispatcher


class DummySupervisor:
    def __init__(self):
        self.calls = []

    def call_module_method(self, module_name, method_name, *args, **kwargs):
        self.calls.append((module_name, method_name, args, kwargs))
        return "remote-result"


def _make_context(runtime_enabled=True, local_group="default"):
    local_module_obj = SimpleNamespace(value="local")
    module_manager = SimpleNamespace(
        runtime_modules={
            "local_module": {
                "group": local_group,
                "mode": "gevent",
                "restart_policy": "always",
            },
            "remote_module": {
                "group": "group_b",
                "mode": "threaded",
                "restart_policy": "always",
            },
        },
        descriptors={},
        modules={
            "local_module": SimpleNamespace(module=local_module_obj),
            "remote_module": SimpleNamespace(module=SimpleNamespace()),
        },
    )
    context = SimpleNamespace(
        settings={
            "modules": {
                "runtime": {
                    "enabled": runtime_enabled,
                    "local_group": local_group,
                }
            }
        },
        module_manager=module_manager,
        runtime_supervisor=DummySupervisor(),
    )
    return context


def test_get_module_proxy_returns_local_module_for_local_group():
    context = _make_context(runtime_enabled=True, local_group="default")
    dispatcher = RuntimeDispatcher(context)

    proxy = dispatcher.get_module_proxy("local_module")

    assert proxy.value == "local"


def test_get_module_proxy_returns_remote_proxy_for_remote_group():
    context = _make_context(runtime_enabled=True, local_group="default")
    dispatcher = RuntimeDispatcher(context)

    proxy = dispatcher.get_module_proxy("remote_module")
    result = proxy.some_method(1, test=True)

    assert result == "remote-result"
    assert context.runtime_supervisor.calls == [
        ("remote_module", "some_method", (1,), {"test": True})
    ]


def test_runtime_disabled_forces_local_execution_path():
    context = _make_context(runtime_enabled=False, local_group="default")
    dispatcher = RuntimeDispatcher(context)

    assert dispatcher.is_remote_module("remote_module") is False
