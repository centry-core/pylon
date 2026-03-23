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
import pytest


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
    _WorkerSlotManager,
    _WorkerModuleManager,
    _WorkerModuleHolder,
    _WorkerRemoteModuleHolder,
    _WorkerRemoteMethodProxy,
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


def test_worker_module_manager_remote_modules_added_for_non_local():
    mgr = _WorkerModuleManager(
        {},
        all_module_groups={"local_mod": "grp_a", "remote_mod": "grp_b"},
        local_group="grp_a",
    )
    assert "remote_mod" in mgr.modules
    assert isinstance(mgr.modules["remote_mod"], _WorkerRemoteModuleHolder)


def test_worker_module_manager_local_shadows_remote():
    class FakeModule:
        pass

    instance = FakeModule()
    mgr = _WorkerModuleManager(
        {"shared": instance},
        all_module_groups={"shared": "grp_a"},
        local_group="grp_a",
    )
    assert isinstance(mgr.modules["shared"], _WorkerModuleHolder)
    assert mgr.modules["shared"].module is instance


def test_worker_module_manager_runtime_modules_populated():
    mgr = _WorkerModuleManager(
        {},
        all_module_groups={"a": "g1", "b": "g2"},
    )
    assert mgr.runtime_modules == {"a": {"group": "g1"}, "b": {"group": "g2"}}


def test_worker_module_manager_set_rpc_node_enables_remote_call():
    """set_rpc_node wires the RPC node into remote method proxies."""
    calls = []

    class FakeRpcNode:
        def call_with_timeout(self, service, timeout, **kwargs):
            calls.append((service, kwargs))
            return {"__runtime_envelope__": True, "ok": True, "result": 42}

    mgr = _WorkerModuleManager(
        {},
        all_module_groups={"remote_mod": "grp_b"},
    )
    mgr.set_rpc_node(FakeRpcNode(), timeout=5.0)

    result = mgr.modules["remote_mod"].module.do_something("arg1", kwarg1="v")
    assert result == 42
    assert calls[0][0] == "runtime_worker_grp_b_module_call"
    assert calls[0][1]["module"] == "remote_mod"
    assert calls[0][1]["method"] == "do_something"
    assert calls[0][1]["args"] == ["arg1"]
    assert calls[0][1]["kwargs"] == {"kwarg1": "v"}


def test_worker_remote_method_raises_before_rpc_node_set():
    mgr = _WorkerModuleManager(
        {},
        all_module_groups={"remote_mod": "grp_b"},
    )
    # rpc_node still None
    with pytest.raises(RuntimeError, match="Worker RPC not ready"):
        mgr.modules["remote_mod"].module.any_method()


def test_worker_remote_method_raises_on_error_envelope():
    class FakeRpcNode:
        def call_with_timeout(self, service, timeout, **kwargs):
            return {
                "__runtime_envelope__": True,
                "ok": False,
                "error": {"type": "ValueError", "message": "bad input"},
            }

    mgr = _WorkerModuleManager(
        {},
        all_module_groups={"remote_mod": "grp_b"},
    )
    mgr.set_rpc_node(FakeRpcNode(), timeout=5.0)

    with pytest.raises(RuntimeError, match="ValueError: bad input"):
        mgr.modules["remote_mod"].module.method()


def test_worker_remote_module_proxy_private_attr_raises():
    mgr = _WorkerModuleManager(
        {},
        all_module_groups={"remote_mod": "grp_b"},
    )
    with pytest.raises(AttributeError):
        _ = mgr.modules["remote_mod"].module.__private


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


def test_build_worker_context_has_flask_app():
    ctx = _build_worker_context(_make_spec(), {})
    assert hasattr(ctx, "app")
    assert ctx.app is not None


def test_build_worker_context_uses_provided_app():
    provided_app = SimpleNamespace(name="provided")
    ctx = _build_worker_context(_make_spec(), {}, app=provided_app)
    assert ctx.app is provided_app


def test_build_worker_context_has_event_manager():
    ctx = _build_worker_context(_make_spec(), {})
    assert isinstance(ctx.event_manager, _WorkerEventManager)


def test_build_worker_context_has_module_manager():
    class FakeModule:
        pass

    instance = FakeModule()
    ctx = _build_worker_context(_make_spec(), {"beta": instance})
    assert ctx.module_manager.modules["beta"].module is instance


# ---------------------------------------------------------------------------
# _WorkerSlotManager
# ---------------------------------------------------------------------------

def test_worker_slot_manager_run_calls_registered_callback():
    mgr = _WorkerSlotManager()
    results = []

    def cb(slot, payload):
        results.append((slot, payload))
        return "rendered"

    mgr.register_callback("sidebar", cb)
    output = mgr.run_slot("sidebar", {"user": "alice"})

    assert results == [("sidebar", {"user": "alice"})]
    assert output == "rendered"


def test_worker_slot_manager_unregister_stops_callback():
    mgr = _WorkerSlotManager()
    calls = []

    def cb(slot, payload):
        calls.append(slot)
        return "x"

    mgr.register_callback("nav", cb)
    mgr.unregister_callback("nav", cb)
    output = mgr.run_slot("nav", None)

    assert calls == []
    assert output == ""


def test_worker_slot_manager_run_unknown_slot_returns_empty():
    mgr = _WorkerSlotManager()
    assert mgr.run_slot("no.such.slot") == ""


def test_worker_slot_manager_multiple_callbacks_joined():
    mgr = _WorkerSlotManager()
    mgr.register_callback("footer", lambda *_: "A")
    mgr.register_callback("footer", lambda *_: "B")
    assert mgr.run_slot("footer") == "A\nB"


def test_worker_slot_manager_callback_exception_is_swallowed():
    mgr = _WorkerSlotManager()

    def bad_cb(slot, payload):
        raise ValueError("kaboom")

    mgr.register_callback("x", bad_cb)
    output = mgr.run_slot("x")  # must not propagate
    assert output == ""


def test_worker_slot_manager_callback_returning_none_excluded():
    mgr = _WorkerSlotManager()
    mgr.register_callback("y", lambda *_: None)
    assert mgr.run_slot("y") == ""


def test_build_worker_context_has_slot_manager():
    ctx = _build_worker_context(_make_spec(), {})
    assert isinstance(ctx.slot_manager, _WorkerSlotManager)


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
