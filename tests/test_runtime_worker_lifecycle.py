#!/usr/bin/python
# coding=utf-8

import sys
import types


def _install_centry_stubs():
    if "centry_logging" in sys.modules:
        return
    log_stub = types.SimpleNamespace(
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


def _install_runtime_deps_stubs():
    if "flask" not in sys.modules:
        flask_mod = types.ModuleType("flask")
        flask_mod.Flask = object
        flask_mod.make_response = lambda payload: payload
        sys.modules["flask"] = flask_mod
    if "arbiter" not in sys.modules:
        arbiter_mod = types.ModuleType("arbiter")
        arbiter_mod.MockEventNode = object
        arbiter_mod.ZeroMQEventNode = object
        arbiter_mod.RpcNode = object
        sys.modules["arbiter"] = arbiter_mod


_install_centry_stubs()
_install_runtime_deps_stubs()

from pylon.core.tools.runtime.worker import (
    _init_worker_modules,
    _deinit_worker_modules,
)


class RecorderModule:
    def __init__(self, name, fail_at=None):
        self.name = name
        self.fail_at = fail_at
        self.events = []

    def init(self):
        self.events.append("init")
        if self.fail_at == "init":
            raise RuntimeError("init fail")

    def ready(self):
        self.events.append("ready")
        if self.fail_at == "ready":
            raise RuntimeError("ready fail")

    def unready(self):
        self.events.append("unready")
        if self.fail_at == "unready":
            raise RuntimeError("unready fail")

    def deinit(self):
        self.events.append("deinit")
        if self.fail_at == "deinit":
            raise RuntimeError("deinit fail")


def test_init_worker_modules_calls_init_and_ready_in_order():
    modules = {
        "a": RecorderModule("a"),
        "b": RecorderModule("b", fail_at="init"),
        "c": RecorderModule("c"),
    }

    initialized = _init_worker_modules(modules, ["a", "b", "c"])

    assert initialized == ["a", "c"]
    assert modules["a"].events == ["init", "ready"]
    assert modules["b"].events == ["init"]
    assert modules["c"].events == ["init", "ready"]


def test_deinit_worker_modules_runs_reverse_order_and_tolerates_errors():
    modules = {
        "a": RecorderModule("a"),
        "c": RecorderModule("c", fail_at="unready"),
    }

    _deinit_worker_modules(modules, ["a", "c"])

    # c is first (reverse), even though unready fails we still call deinit.
    assert modules["c"].events == ["unready", "deinit"]
    assert modules["a"].events == ["unready", "deinit"]
