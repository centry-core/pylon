#!/usr/bin/python
# coding=utf-8
# pyright: reportMissingImports=false

#   Copyright 2026 getcarrier.io
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Runtime worker process bootstrap """

import os
import json
import sys
import types
import signal
import threading
import importlib
import traceback
from types import SimpleNamespace

import arbiter  # pylint: disable=E0401
import flask  # pylint: disable=E0401

from pylon.core.tools import log
from pylon.core.tools.context import Context


def _load_worker_spec():
    raw_data = os.environ.get("PYLON_RUNTIME_WORKER_SPEC", "")
    if not raw_data:
        raise RuntimeError("Missing PYLON_RUNTIME_WORKER_SPEC")
    return json.loads(raw_data)


def _apply_runtime_mode(runtime_mode):
    """Apply worker runtime mode behavior and return effective mode string."""
    if runtime_mode == "threaded":
        return "threaded"
    if runtime_mode == "gevent":
        try:
            import gevent.monkey  # pylint: disable=E0401,C0415
            gevent.monkey.patch_all()
            return "gevent"
        except:  # pylint: disable=W0702
            log.warning(
                "Runtime mode is 'gevent' but monkey patching failed; "
                "continuing in compatibility mode"
            )
            return "gevent-unavailable"
    log.warning("Unknown runtime_mode '%s', using threaded compatibility", runtime_mode)
    return "threaded"


def _make_event_node(zmq_config):
    if not zmq_config.get("enabled", False):
        return arbiter.make_event_node({"type": "MockEventNode"})
    return arbiter.make_event_node({
        "type": "ZeroMQEventNode",
        "connect_sub": zmq_config.get("connect_sub", "tcp://127.0.0.1:5010"),
        "connect_push": zmq_config.get("connect_push", "tcp://127.0.0.1:5011"),
        "topic": zmq_config.get("topic", "events"),
    })


def _activate_import_paths(worker_spec):
    plugins_path = worker_spec.get("plugins_path", None)
    module_specs = worker_spec.get("module_specs", {})
    if plugins_path and os.path.isdir(plugins_path):
        if "plugins" not in sys.modules:
            sys.modules["plugins"] = types.ModuleType("plugins")
            sys.modules["plugins"].__path__ = []
        if plugins_path not in sys.modules["plugins"].__path__:
            sys.modules["plugins"].__path__.append(plugins_path)
    for module_name in worker_spec.get("modules", []):
        spec = module_specs.get(module_name, {})
        requirements_path = spec.get("requirements_path", None)
        loader_path = spec.get("loader_path", None)
        if requirements_path and requirements_path not in sys.path and os.path.isdir(requirements_path):
            sys.path.insert(0, requirements_path)
        if loader_path:
            loader_parent = os.path.dirname(loader_path)
            if loader_parent and loader_parent not in sys.path and os.path.isdir(loader_parent):
                sys.path.insert(0, loader_parent)


class _WorkerEventManager:  # pylint: disable=R0903
    """Local-only event manager for runtime workers."""

    def __init__(self):
        self._listeners = {}  # event_name -> [callable]

    def register_listener(self, event, listener):
        self._listeners.setdefault(event, []).append(listener)

    def unregister_listener(self, event, listener):
        listeners = self._listeners.get(event, [])
        if listener in listeners:
            listeners.remove(listener)

    def fire_event(self, event, payload=None):
        for listener in list(self._listeners.get(event, [])):
            try:
                listener(None, event, payload)
            except:  # pylint: disable=W0702
                log.exception("Worker event listener raised: %s", event)


class _WorkerSlotManager:  # pylint: disable=R0903
    """Local-only slot manager for runtime workers.

    Callbacks registered here are called directly within the worker process
    with no cross-process dispatch.  The interface mirrors SlotManager so
    plugins can call register_callback / unregister_callback / run_slot
    without any changes.
    """

    def __init__(self):
        self._callbacks = {}  # slot -> [callable]

    def register_callback(self, slot, callback):
        self._callbacks.setdefault(slot, []).append(callback)

    def unregister_callback(self, slot, callback):
        slot_cbs = self._callbacks.get(slot, [])
        if callback in slot_cbs:
            slot_cbs.remove(callback)

    def run_slot(self, slot, payload=None):
        results = []
        for cb in list(self._callbacks.get(slot, [])):
            try:
                result = cb(slot, payload)
                if result is not None:
                    results.append(result)
            except:  # pylint: disable=W0702
                log.exception("Worker slot callback raised: %s", slot)
        return "\n".join(results)


class _WorkerModuleHolder:  # pylint: disable=R0903
    """Mimics context.module_manager.modules[name].module for local worker instances."""

    def __init__(self, module_instance):
        self.module = module_instance


class _WorkerRemoteMethodProxy:  # pylint: disable=R0903
    """Callable that dispatches a single method call to a remote worker via RPC."""

    def __init__(self, module_manager, group, module_name, method_name):
        self._module_manager = module_manager
        self._group = group
        self._module_name = module_name
        self._method_name = method_name

    def __call__(self, *args, **kwargs):
        rpc_node = self._module_manager._rpc_node  # pylint: disable=W0212
        if rpc_node is None:
            raise RuntimeError(
                f"Worker RPC not ready: cannot call "
                f"{self._module_name}.{self._method_name}"
            )
        result = rpc_node.call_with_timeout(
            f"runtime_worker_{self._group}_module_call",
            timeout=self._module_manager._rpc_timeout,  # pylint: disable=W0212
            module=self._module_name,
            method=self._method_name,
            args=list(args),
            kwargs=kwargs,
            source="worker-cross-group",
        )
        if isinstance(result, dict) and result.get("__runtime_envelope__", False):
            if result.get("ok", False):
                return result.get("result", None)
            error_data = result.get("error", {})
            raise RuntimeError(
                f"{error_data.get('type', 'RuntimeError')}: "
                f"{error_data.get('message', 'call failed')}"
            )
        return result


class _WorkerRemoteModuleProxy:  # pylint: disable=R0903
    """Attribute proxy that returns _WorkerRemoteMethodProxy for any method name."""

    def __init__(self, module_manager, group, module_name):
        self._module_manager = module_manager
        self._group = group
        self._module_name = module_name

    def __getattr__(self, method_name):
        if method_name.startswith("_"):
            raise AttributeError(method_name)
        return _WorkerRemoteMethodProxy(
            self._module_manager, self._group, self._module_name, method_name
        )


class _WorkerRemoteModuleHolder:  # pylint: disable=R0903
    """Holder whose .module attribute is a _WorkerRemoteModuleProxy."""

    def __init__(self, module_manager, group, module_name):
        self.module = _WorkerRemoteModuleProxy(module_manager, group, module_name)


class _WorkerModuleManager:
    """Module manager for worker processes.

    Exposes local module instances directly and wraps remote modules (those
    assigned to other runtime groups) with an RPC-dispatching proxy so plugin
    code can call ``context.module_manager.modules[name].module.method()``
    regardless of where the target module lives.
    """

    def __init__(self, module_instances, all_module_groups=None, local_group=None):
        _ = local_group
        self._rpc_node = None
        self._rpc_timeout = 30.0
        local = {
            name: _WorkerModuleHolder(inst)
            for name, inst in module_instances.items()
        }
        remote = {}
        if all_module_groups:
            for module_name, group_name in all_module_groups.items():
                if module_name not in local:
                    remote[module_name] = _WorkerRemoteModuleHolder(
                        self, group_name, module_name
                    )
        self.modules = {**remote, **local}
        self.descriptors = {}
        self.runtime_modules = (
            {name: {"group": grp} for name, grp in all_module_groups.items()}
            if all_module_groups else {}
        )

    def set_rpc_node(self, rpc_node, timeout=30.0):
        """Wire in the arbiter RpcNode after it has been started."""
        self._rpc_node = rpc_node
        self._rpc_timeout = timeout


class _WorkerContext(Context):
    """Rich context object for runtime workers."""


def _build_worker_context(worker_spec, module_instances, app=None):
    """Build a rich Context for worker module instances."""
    if app is None:
        runtime_group = worker_spec.get("runtime_group", "unknown")
        app = flask.Flask(f"runtime_worker_{runtime_group}")
    context = _WorkerContext()
    runtime_group = worker_spec.get("runtime_group", "unknown")
    context.id = worker_spec.get("node_id", "unknown")
    context.node_name = worker_spec.get("node_name", f"runtime_worker_{runtime_group}")
    context.settings = worker_spec.get("settings", {})
    context.url_prefix = worker_spec.get("url_prefix", "")
    context.pylon_version = worker_spec.get("pylon_version", "unknown")
    context.runtime_worker = True
    context.runtime_group = runtime_group
    context.app = app
    context.event_manager = _WorkerEventManager()
    context.slot_manager = _WorkerSlotManager()
    _all_module_groups = worker_spec.get("all_module_groups", {})
    _local_group = worker_spec.get("runtime_group", "default")
    context.module_manager = _WorkerModuleManager(
        module_instances,
        all_module_groups=_all_module_groups,
        local_group=_local_group,
    )
    return context


def _bootstrap_tools_module(context):
    """Make `import tools; tools.context` work inside workers."""
    if "tools" not in sys.modules:
        sys.modules["tools"] = types.ModuleType("tools")
        sys.modules["tools"].__path__ = []
    setattr(sys.modules["tools"], "context", context)
    setattr(sys.modules["tools"], "log", log)


def _build_worker_modules(worker_spec, app=None):
    modules = worker_spec.get("modules", [])
    module_specs = worker_spec.get("module_specs", {})
    runtime_group = worker_spec.get("runtime_group", "unknown")
    if app is None:
        app = flask.Flask(f"runtime_worker_{runtime_group}")
    # Pre-build a minimal context to instantiate modules; will be enriched below.
    _proto_context = SimpleNamespace(
        id=worker_spec.get("node_id", "unknown"),
        node_name=worker_spec.get("node_name", f"runtime_worker_{runtime_group}"),
        settings=worker_spec.get("settings", {}),
        url_prefix=worker_spec.get("url_prefix", ""),
        app=app,
        runtime_worker=True,
        runtime_group=runtime_group,
    )
    module_instances = {}
    module_packages = {}
    for module_name in modules:
        try:
            module_pkg = importlib.import_module(f"plugins.{module_name}.module")
            module_packages[module_name] = module_pkg
        except:  # pylint: disable=W0702
            log.exception("Failed to import worker module package: %s", module_name)
            continue
        module_class = getattr(module_pkg, "Module", None)
        if module_class is None:
            continue
        descriptor = SimpleNamespace(
            name=module_name,
            metadata=module_specs.get(module_name, {}).get("metadata", {}),
            state={},
            config={},
        )
        try:
            module_instances[module_name] = module_class(
                context=_proto_context,
                descriptor=descriptor,
            )
        except:  # pylint: disable=W0702
            log.exception("Failed to instantiate worker module class: %s", module_name)
    # Now build the rich context and patch it into every module instance.
    rich_context = _build_worker_context(worker_spec, module_instances, app=app)
    _bootstrap_tools_module(rich_context)
    for module_obj in module_instances.values():
        if hasattr(module_obj, "context"):
            try:
                module_obj.context = rich_context
            except:  # pylint: disable=W0702
                pass
    _all_module_groups = worker_spec.get("all_module_groups", {})
    rich_context.module_manager = _WorkerModuleManager(
        module_instances,
        all_module_groups=_all_module_groups,
        local_group=runtime_group,
    )
    return module_instances, module_packages, rich_context


def _init_worker_modules(module_instances, module_order):
    initialized_modules = []
    for module_name in module_order:
        if module_name not in module_instances:
            continue
        module_obj = module_instances[module_name]
        try:
            if hasattr(module_obj, "init"):
                module_obj.init()
            if hasattr(module_obj, "ready"):
                module_obj.ready()
        except:  # pylint: disable=W0702
            log.exception("Worker module init/ready failed: %s", module_name)
            continue
        initialized_modules.append(module_name)
    return initialized_modules


def _deinit_worker_modules(module_instances, initialized_modules):
    for module_name in reversed(initialized_modules):
        if module_name not in module_instances:
            continue
        module_obj = module_instances[module_name]
        try:
            if hasattr(module_obj, "unready"):
                module_obj.unready()
        except:  # pylint: disable=W0702
            log.exception("Worker module unready failed: %s", module_name)
        try:
            if hasattr(module_obj, "deinit"):
                module_obj.deinit()
        except:  # pylint: disable=W0702
            log.exception("Worker module deinit failed: %s", module_name)


def _success_envelope(*, result=None, response=None):
    return {
        "__runtime_envelope__": True,
        "ok": True,
        "result": result,
        "response": response,
    }


def _error_envelope(exc, *, status=500):
    message = str(exc) or exc.__class__.__name__
    return {
        "__runtime_envelope__": True,
        "ok": False,
        "error": {
            "type": exc.__class__.__name__,
            "message": message,
            "traceback": traceback.format_exc(),
        },
        "response": {
            "status": status,
            "headers": [("Content-Type", "text/plain; charset=utf-8")],
            "body": f"{exc.__class__.__name__}: {message}".encode(),
        },
    }


def run_worker():
    """Runtime worker process entrypoint."""
    worker_spec = _load_worker_spec()
    runtime_group = worker_spec.get("runtime_group", "unknown")
    runtime_mode = worker_spec.get("runtime_mode", "gevent")
    effective_runtime_mode = _apply_runtime_mode(runtime_mode)
    modules = worker_spec.get("modules", [])
    route_app = flask.Flask(f"runtime_worker_{runtime_group}")
    stop_event = threading.Event()
    worker_id = f"{worker_spec.get('node_id', 'unknown')}:{runtime_group}"
    _activate_import_paths(worker_spec)
    module_instances, module_packages, worker_context = _build_worker_modules(
        worker_spec,
        app=route_app,
    )
    initialized_modules = _init_worker_modules(module_instances, modules)

    def _sigterm_handler(_signal_num, _stack_frame):
        stop_event.set()

    signal.signal(signal.SIGTERM, _sigterm_handler)
    signal.signal(signal.SIGINT, _sigterm_handler)

    log.info(
        "Runtime worker started [group=%s, mode=%s, effective_mode=%s, modules=%s]",
        runtime_group,
        runtime_mode,
        effective_runtime_mode,
        ",".join(modules),
    )

    event_node = _make_event_node(worker_spec.get("zmq", {}))
    rpc_node = arbiter.RpcNode(
        event_node,
        id_prefix=f"runtime_worker_{runtime_group}_",
    )

    def _ping(payload=None):
        _ = payload
        return {
            "ok": True,
            "worker_id": worker_id,
            "runtime_group": runtime_group,
            "runtime_mode": runtime_mode,
            "effective_runtime_mode": effective_runtime_mode,
            "modules": modules,
            "initialized_modules": initialized_modules,
        }

    def _describe(payload=None):
        _ = payload
        return {
            "worker_id": worker_id,
            "runtime_group": runtime_group,
            "runtime_mode": runtime_mode,
            "effective_runtime_mode": effective_runtime_mode,
            "module_count": len(modules),
            "modules": modules,
            "initialized_modules": initialized_modules,
        }

    def _module_call(module=None, method=None, args=None, kwargs=None, source=None):
        try:
            _ = source
            if module not in modules:
                raise RuntimeError(f"Module is not assigned to this worker: {module}")
            if args is None:
                args = []
            if kwargs is None:
                kwargs = {}
            if module in module_instances and hasattr(module_instances[module], method):
                target = getattr(module_instances[module], method)
                return _success_envelope(result=target(*args, **kwargs))
            if module in module_packages and hasattr(module_packages[module], method):
                target = getattr(module_packages[module], method)
                return _success_envelope(result=target(*args, **kwargs))
            rpc_name = f"{module}_{method}"
            return _success_envelope(result=rpc_node.call_with_timeout(
                rpc_name,
                timeout=float(worker_spec.get("rpc_timeout_sec", 30.0)),
                *args,
                **kwargs,
            ))
        except:  # pylint: disable=W0702
            try:
                module_pkg = importlib.import_module(f"plugins.{module}.module")
                target = getattr(module_pkg, method)
                return _success_envelope(result=target(*args, **kwargs))
            except Exception as exc:  # pylint: disable=W0718
                return _error_envelope(exc)

    def _route_call(  # pylint: disable=R0913
            module=None,
            callable_module=None,
            callable_name=None,
            module_routes=True,
            request_data=None,
            source=None,
        ):
        try:
            _ = source
            if module not in modules:
                raise RuntimeError(f"Module is not assigned to this worker: {module}")
            if request_data is None:
                request_data = {}
            target_pkg = importlib.import_module(callable_module)
            target_callable = getattr(target_pkg, callable_name)
            route_kwargs = request_data.get("route_kwargs", {})
            method = request_data.get("method", "GET")
            path = request_data.get("path", "/")
            query_string = request_data.get("query_string", b"")
            headers = request_data.get("headers", {})
            body = request_data.get("body", b"")
            content_type = request_data.get("content_type", None)
            with route_app.test_request_context(
                    path=path,
                    method=method,
                    query_string=query_string,
                    headers=headers,
                    data=body,
                    content_type=content_type,
            ):
                if module_routes:
                    if module not in module_instances:
                        raise RuntimeError(f"No module instance available in worker: {module}")
                    view_rv = target_callable(module_instances[module], **route_kwargs)
                else:
                    view_rv = target_callable(**route_kwargs)
                response = flask.make_response(view_rv)
                return _success_envelope(response={
                    "status": response.status_code,
                    "headers": list(response.headers.items()),
                    "body": response.get_data(),
                })
        except Exception as exc:  # pylint: disable=W0718
            return _error_envelope(exc)

    def _event_call(
            module=None,
            callable_module=None,
            callable_name=None,
            event_name=None,
            event_payload=None,
            source=None,
        ):
        try:
            _ = source
            if module not in modules:
                raise RuntimeError(f"Module is not assigned to this worker: {module}")
            target_pkg = importlib.import_module(callable_module)
            target_callable = getattr(target_pkg, callable_name)
            if module not in module_instances:
                raise RuntimeError(f"No module instance available in worker: {module}")
            module_obj = module_instances[module]
            context_obj = getattr(module_obj, "context", None)
            return _success_envelope(result=target_callable(module_obj, context_obj, event_name, event_payload))
        except Exception as exc:  # pylint: disable=W0718
            return _error_envelope(exc)

    def _slot_call(
            module=None,
            callable_module=None,
            callable_name=None,
            slot=None,
            payload=None,
            source=None,
        ):
        try:
            _ = source
            if module not in modules:
                raise RuntimeError(f"Module is not assigned to this worker: {module}")
            target_pkg = importlib.import_module(callable_module)
            target_callable = getattr(target_pkg, callable_name)
            if module not in module_instances:
                raise RuntimeError(f"No module instance available in worker: {module}")
            module_obj = module_instances[module]
            context_obj = getattr(module_obj, "context", None)
            return _success_envelope(result=target_callable(module_obj, context_obj, slot, payload))
        except Exception as exc:  # pylint: disable=W0718
            return _error_envelope(exc)

    def _api_call(  # pylint: disable=R0913
            module=None,
            api_version=None,
            resource_name=None,
            method_name=None,
            api_kwargs=None,
            request_data=None,
            source=None,
        ):
        try:
            _ = source
            if module not in modules:
                raise RuntimeError(f"Module is not assigned to this worker: {module}")
            if api_kwargs is None:
                api_kwargs = {}
            if request_data is None:
                request_data = {}
            module_pkg = importlib.import_module(
                f"plugins.{module}.api.{api_version}.{resource_name}"
            )
            resource_cls = getattr(module_pkg, "API")
            method = request_data.get("method", "GET")
            path = request_data.get("path", "/")
            query_string = request_data.get("query_string", b"")
            headers = request_data.get("headers", {})
            body = request_data.get("body", b"")
            content_type = request_data.get("content_type", None)
            module_obj = module_instances.get(module, None)
            try:
                resource_obj = resource_cls(module=module_obj)
            except TypeError:
                resource_obj = resource_cls()
            with route_app.test_request_context(
                    path=path,
                    method=method,
                    query_string=query_string,
                    headers=headers,
                    data=body,
                    content_type=content_type,
            ):
                handler = getattr(resource_obj, method_name)
                view_rv = handler(**api_kwargs)
                response = flask.make_response(view_rv)
                return _success_envelope(response={
                    "status": response.status_code,
                    "headers": list(response.headers.items()),
                    "body": response.get_data(),
                })
        except Exception as exc:  # pylint: disable=W0718
            return _error_envelope(exc)

    event_node.start()
    rpc_node.start()
    worker_context.module_manager.set_rpc_node(
        rpc_node,
        timeout=float(worker_spec.get("rpc_timeout_sec", 30.0)),
    )
    rpc_node.register(_ping, name=f"runtime_worker_{runtime_group}_ping")
    rpc_node.register(_describe, name=f"runtime_worker_{runtime_group}_describe")
    rpc_node.register(_module_call, name=f"runtime_worker_{runtime_group}_module_call")
    rpc_node.register(_route_call, name=f"runtime_worker_{runtime_group}_route_call")
    rpc_node.register(_event_call, name=f"runtime_worker_{runtime_group}_event_call")
    rpc_node.register(_slot_call, name=f"runtime_worker_{runtime_group}_slot_call")
    rpc_node.register(_api_call, name=f"runtime_worker_{runtime_group}_api_call")

    try:
        while not stop_event.wait(1.0):
            pass
    finally:
        _deinit_worker_modules(module_instances, initialized_modules)
        rpc_node.unregister(_api_call, name=f"runtime_worker_{runtime_group}_api_call")
        rpc_node.unregister(_slot_call, name=f"runtime_worker_{runtime_group}_slot_call")
        rpc_node.unregister(_event_call, name=f"runtime_worker_{runtime_group}_event_call")
        rpc_node.unregister(_route_call, name=f"runtime_worker_{runtime_group}_route_call")
        rpc_node.unregister(_module_call, name=f"runtime_worker_{runtime_group}_module_call")
        rpc_node.unregister(_describe, name=f"runtime_worker_{runtime_group}_describe")
        rpc_node.unregister(_ping, name=f"runtime_worker_{runtime_group}_ping")
        rpc_node.stop()
        event_node.stop()
        log.info("Runtime worker stopped [group=%s]", runtime_group)


def main():
    """CLI entrypoint for worker process."""
    try:
        run_worker()
    except SystemExit:
        raise
    except:  # pylint: disable=W0702
        log.exception("Runtime worker crashed")
        raise


if __name__ == "__main__":
    main()
