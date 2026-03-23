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
from types import SimpleNamespace

import arbiter  # pylint: disable=E0401
import flask  # pylint: disable=E0401

from pylon.core.tools import log


def _load_worker_spec():
    raw_data = os.environ.get("PYLON_RUNTIME_WORKER_SPEC", "")
    if not raw_data:
        raise RuntimeError("Missing PYLON_RUNTIME_WORKER_SPEC")
    return json.loads(raw_data)


def _make_event_node(zmq_config):
    if not zmq_config.get("enabled", False):
        return arbiter.MockEventNode()
    return arbiter.ZeroMQEventNode(
        connect_sub=zmq_config.get("connect_sub", "tcp://127.0.0.1:5010"),
        connect_push=zmq_config.get("connect_push", "tcp://127.0.0.1:5011"),
        topic=zmq_config.get("topic", "events"),
    )


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


def _build_worker_modules(worker_spec):
    modules = worker_spec.get("modules", [])
    module_specs = worker_spec.get("module_specs", {})
    runtime_group = worker_spec.get("runtime_group", "unknown")
    context = SimpleNamespace(
        id=worker_spec.get("node_id", "unknown"),
        node_name=f"runtime_worker_{runtime_group}",
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
                context=context,
                descriptor=descriptor,
            )
        except:  # pylint: disable=W0702
            log.exception("Failed to instantiate worker module class: %s", module_name)
    return module_instances, module_packages


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


def run_worker():
    """Runtime worker process entrypoint."""
    worker_spec = _load_worker_spec()
    runtime_group = worker_spec.get("runtime_group", "unknown")
    runtime_mode = worker_spec.get("runtime_mode", "gevent")
    modules = worker_spec.get("modules", [])
    stop_event = threading.Event()
    worker_id = f"{worker_spec.get('node_id', 'unknown')}:{runtime_group}"
    _activate_import_paths(worker_spec)
    module_instances, module_packages = _build_worker_modules(worker_spec)
    initialized_modules = _init_worker_modules(module_instances, modules)
    route_app = flask.Flask(f"runtime_worker_{runtime_group}")

    def _sigterm_handler(_signal_num, _stack_frame):
        stop_event.set()

    signal.signal(signal.SIGTERM, _sigterm_handler)
    signal.signal(signal.SIGINT, _sigterm_handler)

    log.info(
        "Runtime worker started [group=%s, mode=%s, modules=%s]",
        runtime_group,
        runtime_mode,
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
            "modules": modules,
            "initialized_modules": initialized_modules,
        }

    def _describe(payload=None):
        _ = payload
        return {
            "worker_id": worker_id,
            "runtime_group": runtime_group,
            "runtime_mode": runtime_mode,
            "module_count": len(modules),
            "modules": modules,
            "initialized_modules": initialized_modules,
        }

    def _module_call(module=None, method=None, args=None, kwargs=None, source=None):
        _ = source
        if module not in modules:
            raise RuntimeError(f"Module is not assigned to this worker: {module}")
        if args is None:
            args = []
        if kwargs is None:
            kwargs = {}
        if module in module_instances and hasattr(module_instances[module], method):
            target = getattr(module_instances[module], method)
            return target(*args, **kwargs)
        if module in module_packages and hasattr(module_packages[module], method):
            target = getattr(module_packages[module], method)
            return target(*args, **kwargs)
        # Transitional behavior: bridge module.method to existing RPC naming when available.
        rpc_name = f"{module}_{method}"
        try:
            return rpc_node.call_with_timeout(
                rpc_name,
                timeout=float(worker_spec.get("rpc_timeout_sec", 30.0)),
                *args,
                **kwargs,
            )
        except:  # pylint: disable=W0702
            # Fallback for plugin module-level helper functions, if present.
            module_pkg = importlib.import_module(f"plugins.{module}.module")
            target = getattr(module_pkg, method)
            return target(*args, **kwargs)

    def _route_call(  # pylint: disable=R0913
            module=None,
            callable_module=None,
            callable_name=None,
            module_routes=True,
            request_data=None,
            source=None,
        ):
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
            return {
                "status": response.status_code,
                "headers": list(response.headers.items()),
                "body": response.get_data(),
            }

    def _event_call(
            module=None,
            callable_module=None,
            callable_name=None,
            event_name=None,
            event_payload=None,
            source=None,
        ):
        _ = source
        if module not in modules:
            raise RuntimeError(f"Module is not assigned to this worker: {module}")
        target_pkg = importlib.import_module(callable_module)
        target_callable = getattr(target_pkg, callable_name)
        if module not in module_instances:
            raise RuntimeError(f"No module instance available in worker: {module}")
        module_obj = module_instances[module]
        context_obj = getattr(module_obj, "context", None)
        return target_callable(module_obj, context_obj, event_name, event_payload)

    def _slot_call(
            module=None,
            callable_module=None,
            callable_name=None,
            slot=None,
            payload=None,
            source=None,
        ):
        _ = source
        if module not in modules:
            raise RuntimeError(f"Module is not assigned to this worker: {module}")
        target_pkg = importlib.import_module(callable_module)
        target_callable = getattr(target_pkg, callable_name)
        if module not in module_instances:
            raise RuntimeError(f"No module instance available in worker: {module}")
        module_obj = module_instances[module]
        context_obj = getattr(module_obj, "context", None)
        return target_callable(module_obj, context_obj, slot, payload)

    def _api_call(  # pylint: disable=R0913
            module=None,
            api_version=None,
            resource_name=None,
            method_name=None,
            api_kwargs=None,
            request_data=None,
            source=None,
        ):
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
            return {
                "status": response.status_code,
                "headers": list(response.headers.items()),
                "body": response.get_data(),
            }

    event_node.start()
    rpc_node.start()
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
