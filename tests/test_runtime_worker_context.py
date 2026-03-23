#!/usr/bin/python
# coding=utf-8
# pyright: reportMissingImports=false

"""
Tests for the richer worker context bootstrap introduced in
pylon/core/tools/runtime/worker.py.

No real subprocess is involved; all helpers are exercised directly.
"""

import sys
import types
import importlib.util
from types import SimpleNamespace


# ---------------------------------------------------------------------------
# Minimal stubs for optional deps that may not be installed
# ---------------------------------------------------------------------------

def _install_arbiter_stubs():
    if "arbiter" in sys.modules:
        return
    if importlib.util.find_spec("arbiter") is not None:
        return
    arbiter_mod = types.ModuleType("arbiter")
    arbiter_mod.MockEventNode = object
    sys.modules["arbiter"] = arbiter_mod


def _install_centry_stubs():
    if "centry_logging" in sys.modules:
        return
    log_stub = SimpleNamespace(
        exception=lambda *a, **kw: None,
        info=lambda *a, **kw: None,
        warning=lambda *a, **kw: None,
        error=lambda *a, **kw: None,
        debug=lambda *a, **kw: None,
    )
    centry_mod = types.ModuleType("centry_logging")
    centry_mod.log = log_stub
    tools_debug = types.ModuleType("centry_logging.tools.debug")
    filters_string = types.ModuleType("centry_logging.filters.string")
    tools_debug.DebugLogStream = object
    filters_string.StringFilter = object
    sys.modules["centry_logging"] = centry_mod
    sys.modules["centry_logging.tools"] = types.ModuleType("centry_logging.tools")
    sys.modules["centry_logging.tools.debug"] = tools_debug
    sys.modules["centry_logging.filters"] = types.ModuleType("centry_logging.filters")
    sys.modules["centry_logging.filters.string"] = filters_string


_install_centry_stubs()
_install_arbiter_stubs()

from pylon.core.tools.runtime.worker import (  # noqa: E402
    _WorkerEventManager,
    _WorkerModuleManager,
    _WorkerModuleHolder,
    _WorkerContext,
    _build_worker_context,
    _bootstrap_tools_module,
)


# ---------------------------------------------------------------------------
# _WorkerEventManager
# ---------------------------------------------------------------------------

def test_worker_event_manager_fire_calls_registered_listener():
    mgr = _WorkerEventManager()
    received = []

    def handler(ctx, event_name, payload):
        received.append((event_name, payload))

    mgr.register_listener("build.done", handler)
    mgr.fire_event("build.done", {"ok": True})

    assert received == [("build.done", {"ok": True})]


def test_worker_event_manager_unregister_stops_delivery():
    mgr = _WorkerEventManager()
    received = []

    def handler(ctx, event_name, payload):
        received.append(event_name)

    mgr.register_listener("deploy", handler)
    mgr.unregister_listener("deploy", handler)
    mgr.fire_event("deploy", None)

    assert received == []


def test_worker_event_manager_fire_unknown_event_is_silent():
    mgr = _WorkerEventManager()
    mgr.fire_event("no.such.event", None)  # must not raise


def test_worker_event_manager_listener_exception_is_swallowed():
    mgr = _WorkerEventManager()

    def bad_handler(ctx, event_name, payload):
        raise RuntimeError("boom")

    mgr.register_listener("x", bad_handler)
    mgr.fire_event("x", None)  # must not propagate


# ---------------------------------------------------------------------------
# _WorkerModuleManager
# ---------------------------------------------------------------------------

def test_worker_module_manager_exposes_instances_via_module_attr():
    class FakeModule:
        pass

    instance = FakeModule()
    mgr = _WorkerModuleManager({"alpha": instance})

    assert mgr.modules["alpha"].module is instance
    assert isinstance(mgr.modules["alpha"], _WorkerModuleHolder)


def test_worker_module_manager_empty_descriptors_and_runtime_modules():
    mgr = _WorkerModuleManager({})
    assert mgr.descriptors == {}
    assert mgr.runtime_modules == {}


# ---------------------------------------------------------------------------
# _build_worker_context
# ---------------------------------------------------------------------------

def _make_spec(**overrides):
    base = {
        "node_id": "test-node",
        "node_name": "test-worker",
        "runtime_group": "grp",
        "settings": {"key": "value", "modules": {"runtime": {"enabled": True}}},
        "url_prefix": "/app",
        "pylon_version": "1.2.3",
    }
    base.update(overrides)
    return base


def test_build_worker_context_sets_identity_fields():
    ctx = _build_worker_context(_make_spec(), {})
    assert ctx.id == "test-node"
    assert ctx.node_name == "test-worker"
    assert ctx.runtime_worker is True
    assert ctx.runtime_group == "grp"


def test_build_worker_context_propagates_settings():
    ctx = _build_worker_context(_make_spec(), {})
    assert ctx.settings == {"key": "value", "modules": {"runtime": {"enabled": True}}}


def test_build_worker_context_propagates_url_prefix():
    ctx = _build_worker_context(_make_spec(url_prefix="/custom"), {})
    assert ctx.url_prefix == "/custom"


def test_build_worker_context_propagates_pylon_version():
    ctx = _build_worker_context(_make_spec(pylon_version="9.9.9"), {})
    assert ctx.pylon_version == "9.9.9"


def test_build_worker_context_has_event_manager():
    ctx = _build_worker_context(_make_spec(), {})
    assert isinstance(ctx.event_manager, _WorkerEventManager)


def test_build_worker_context_has_module_manager():
    class FakeModule:
        pass

    instance = FakeModule()
    ctx = _build_worker_context(_make_spec(), {"beta": instance})
    assert ctx.module_manager.modules["beta"].module is instance


def test_build_worker_context_slot_manager_is_none():
    ctx = _build_worker_context(_make_spec(), {})
    assert ctx.slot_manager is None


def test_build_worker_context_is_context_instance():
    ctx = _build_worker_context(_make_spec(), {})
    assert isinstance(ctx, _WorkerContext)


# ---------------------------------------------------------------------------
# _bootstrap_tools_module
# ---------------------------------------------------------------------------

def test_bootstrap_tools_module_makes_tools_importable():
    ctx = _build_worker_context(_make_spec(), {})
    # Remove any pre-existing tools module to test fresh install.
    sys.modules.pop("tools", None)
    _bootstrap_tools_module(ctx)

    import tools  # noqa: PLC0415
    assert tools.context is ctx


def test_bootstrap_tools_module_exposes_log():
    ctx = _build_worker_context(_make_spec(), {})
    sys.modules.pop("tools", None)
    _bootstrap_tools_module(ctx)

    import tools  # noqa: PLC0415
    assert hasattr(tools, "log")


def test_bootstrap_tools_module_is_idempotent():
    ctx = _build_worker_context(_make_spec(), {})
    _bootstrap_tools_module(ctx)
    _bootstrap_tools_module(ctx)  # second call must not raise or duplicate

    import tools  # noqa: PLC0415
    assert tools.context is ctx
