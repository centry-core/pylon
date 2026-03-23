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

""" Runtime dispatch and module import shims """

import sys
import types

import flask  # pylint: disable=E0401
import flask_restful  # pylint: disable=E0401


class RuntimeMethodProxy:  # pylint: disable=R0903
    """Callable proxy for remote module methods."""

    def __init__(self, dispatcher, module_name, method_name):
        self.dispatcher = dispatcher
        self.module_name = module_name
        self.method_name = method_name

    def __call__(self, *args, **kwargs):
        return self.dispatcher.call_module_method(
            self.module_name,
            self.method_name,
            *args,
            **kwargs,
        )


class RuntimeModuleProxy:  # pylint: disable=R0903
    """Attribute proxy for remote module object access."""

    def __init__(self, dispatcher, module_name):
        self.dispatcher = dispatcher
        self.module_name = module_name

    def __getattr__(self, method_name):
        return RuntimeMethodProxy(self.dispatcher, self.module_name, method_name)


class RuntimeImportShimModule(types.ModuleType):
    """Module-like shim that forwards attribute access to runtime dispatcher."""

    def __init__(self, dispatcher, module_name):
        super().__init__(f"plugins.{module_name}.runtime_shim")
        self._dispatcher = dispatcher
        self._module_name = module_name
        self.__package__ = f"plugins.{module_name}"

    def __getattr__(self, attr_name):
        if attr_name.startswith("__"):
            raise AttributeError(attr_name)
        return getattr(self._dispatcher.get_module_proxy(self._module_name), attr_name)


class RuntimeDispatcher:  # pylint: disable=R0903
    """Resolves local vs remote module execution and creates call shims."""

    def __init__(self, context):
        self.context = context
        self._patched_modules = {}

    def _runtime_settings(self):
        return self.context.settings.get("modules", {}).get("runtime", {})

    def _runtime_enabled(self):
        return self._runtime_settings().get("enabled", False)

    def _local_group(self):
        return self._runtime_settings().get("local_group", "default")

    def _module_runtime_data(self, module_name):
        module_manager = self.context.module_manager
        if module_name in module_manager.runtime_modules:
            return module_manager.runtime_modules[module_name]
        if module_name in module_manager.descriptors:
            descriptor = module_manager.descriptors[module_name]
            return {
                "group": descriptor.metadata.get("runtime_group", "default"),
                "mode": descriptor.metadata.get("runtime_mode", "gevent"),
                "restart_policy": descriptor.metadata.get("restart_policy", "always"),
            }
        return None

    def is_remote_module(self, module_name):
        if not self._runtime_enabled():
            return False
        runtime_data = self._module_runtime_data(module_name)
        if runtime_data is None:
            return False
        return runtime_data.get("group", "default") != self._local_group()

    def get_module_proxy(self, module_name):
        module_manager = self.context.module_manager
        if not self.is_remote_module(module_name):
            return module_manager.modules[module_name].module
        return RuntimeModuleProxy(self, module_name)

    def refresh_shims(self):
        """Install or restore direct import shims for remote plugin modules."""
        current_remote_modules = {
            module_name
            for module_name in self.context.module_manager.runtime_modules
            if self.is_remote_module(module_name)
        }
        for module_name in list(self._patched_modules):
            if module_name not in current_remote_modules:
                self._restore_module_shim(module_name)
        for module_name in sorted(current_remote_modules):
            self._install_module_shim(module_name)

    def _install_module_shim(self, module_name):
        module_path = f"plugins.{module_name}.module"
        package_path = f"plugins.{module_name}"
        if module_path not in sys.modules or package_path not in sys.modules:
            return
        real_module = sys.modules[module_path]
        package_module = sys.modules[package_path]
        existing_patch = self._patched_modules.get(module_name, None)
        if existing_patch is not None and existing_patch.get("real_module") is real_module:
            return
        if existing_patch is not None:
            self._restore_module_shim(module_name)
        shim_module = RuntimeImportShimModule(self, module_name)
        patched_attrs = {}
        for attr_name, attr_value in list(real_module.__dict__.items()):
            if attr_name.startswith("_"):
                continue
            if attr_name in ["Module"]:
                continue
            if not callable(attr_value):
                continue
            patched_attrs[attr_name] = attr_value
            setattr(real_module, attr_name, RuntimeMethodProxy(self, module_name, attr_name))
        original_package_module_attr = getattr(package_module, "module", None)
        setattr(package_module, "module", shim_module)
        setattr(package_module, "runtime_shim", shim_module)
        sys.modules[f"plugins.{module_name}.runtime_shim"] = shim_module
        self._patched_modules[module_name] = {
            "real_module": real_module,
            "package_module": package_module,
            "patched_attrs": patched_attrs,
            "original_package_module_attr": original_package_module_attr,
            "shim_module": shim_module,
        }

    def _restore_module_shim(self, module_name):
        patch_data = self._patched_modules.pop(module_name, None)
        if patch_data is None:
            return
        real_module = patch_data["real_module"]
        package_module = patch_data["package_module"]
        for attr_name, attr_value in patch_data["patched_attrs"].items():
            setattr(real_module, attr_name, attr_value)
        if patch_data["original_package_module_attr"] is not None:
            setattr(package_module, "module", patch_data["original_package_module_attr"])
        elif hasattr(package_module, "module"):
            delattr(package_module, "module")
        if hasattr(package_module, "runtime_shim"):
            delattr(package_module, "runtime_shim")
        sys.modules.pop(f"plugins.{module_name}.runtime_shim", None)

    @staticmethod
    def _capture_request_data(route_kwargs=None):
        if route_kwargs is None:
            route_kwargs = {}
        return {
            "method": flask.request.method,
            "path": flask.request.path,
            "query_string": flask.request.query_string,
            "headers": dict(flask.request.headers),
            "body": flask.request.get_data(),
            "content_type": flask.request.content_type,
            "route_kwargs": dict(route_kwargs),
        }

    @staticmethod
    def _is_runtime_envelope(value):
        return isinstance(value, dict) and value.get("__runtime_envelope__", False) is True

    def _unwrap_result_envelope(self, value):
        if not self._is_runtime_envelope(value):
            return value
        if value.get("ok", False):
            return value.get("result", None)
        error_data = value.get("error", {})
        error_type = error_data.get("type", "RuntimeError")
        error_message = error_data.get("message", "Runtime call failed")
        raise RuntimeError(f"{error_type}: {error_message}")

    def _unwrap_response_envelope(self, value):
        if not self._is_runtime_envelope(value):
            return value
        if value.get("ok", False):
            return value.get("response", {})
        error_data = value.get("error", {})
        fallback_response = value.get("response", {})
        if fallback_response:
            return fallback_response
        error_type = error_data.get("type", "RuntimeError")
        error_message = error_data.get("message", "Runtime request failed")
        return {
            "status": 502,
            "headers": [("Content-Type", "text/plain; charset=utf-8")],
            "body": f"{error_type}: {error_message}".encode(),
        }

    def make_api_resource(self, module_name, api_version, resource_name):
        dispatcher = self

        class RuntimeApiProxyResource(flask_restful.Resource):
            def _dispatch_api(self, **api_kwargs):
                request_data = dispatcher._capture_request_data()
                return dispatcher.call_api(
                    module_name=module_name,
                    api_version=api_version,
                    resource_name=resource_name,
                    method_name=flask.request.method.lower(),
                    api_kwargs=api_kwargs,
                    request_data=request_data,
                )

            def get(self, **api_kwargs):
                return self._dispatch_api(**api_kwargs)

            def post(self, **api_kwargs):
                return self._dispatch_api(**api_kwargs)

            def put(self, **api_kwargs):
                return self._dispatch_api(**api_kwargs)

            def patch(self, **api_kwargs):
                return self._dispatch_api(**api_kwargs)

            def delete(self, **api_kwargs):
                return self._dispatch_api(**api_kwargs)

            def options(self, **api_kwargs):
                return self._dispatch_api(**api_kwargs)

            def head(self, **api_kwargs):
                return self._dispatch_api(**api_kwargs)

        RuntimeApiProxyResource.__name__ = \
            f"RuntimeApiProxy_{module_name}_{api_version}_{resource_name}"
        return RuntimeApiProxyResource

    def make_route_view(self, module_name, route_callable, module_routes=True):
        def _route_proxy(**route_kwargs):
            if not self.is_remote_module(module_name):
                if module_routes:
                    module_obj = self.context.module_manager.modules[module_name].module
                    return route_callable(module_obj, **route_kwargs)
                return route_callable(**route_kwargs)
            request_data = self._capture_request_data(route_kwargs)
            return self.call_route(
                module_name,
                callable_module=route_callable.__module__,
                callable_name=route_callable.__name__,
                module_routes=module_routes,
                request_data=request_data,
            )
        _route_proxy.__name__ = route_callable.__name__
        _route_proxy.__module__ = route_callable.__module__
        return _route_proxy

    def call_route(  # pylint: disable=R0913
            self,
            module_name,
            callable_module,
            callable_name,
            module_routes,
            request_data,
        ):
        if not hasattr(self.context, "runtime_supervisor"):
            raise RuntimeError("Runtime supervisor is not initialized")
        response_data = self.context.runtime_supervisor.call_route(
            module_name=module_name,
            callable_module=callable_module,
            callable_name=callable_name,
            module_routes=module_routes,
            request_data=request_data,
        )
        response_data = self._unwrap_response_envelope(response_data)
        view_rv = (
            response_data.get("body", b""),
            response_data.get("status", 500),
            response_data.get("headers", []),
        )
        return flask.make_response(view_rv)

    def call_api(  # pylint: disable=R0913
            self,
            module_name,
            api_version,
            resource_name,
            method_name,
            api_kwargs,
            request_data,
        ):
        if not hasattr(self.context, "runtime_supervisor"):
            raise RuntimeError("Runtime supervisor is not initialized")
        response_data = self.context.runtime_supervisor.call_api(
            module_name=module_name,
            api_version=api_version,
            resource_name=resource_name,
            method_name=method_name,
            api_kwargs=api_kwargs,
            request_data=request_data,
        )
        response_data = self._unwrap_response_envelope(response_data)
        view_rv = (
            response_data.get("body", b""),
            response_data.get("status", 500),
            response_data.get("headers", []),
        )
        return flask.make_response(view_rv)

    def make_event_listener(self, module_name, listener_callable):
        def _event_proxy(context, event_name, event_payload):
            _ = context
            if not self.is_remote_module(module_name):
                module_obj = self.context.module_manager.modules[module_name].module
                return listener_callable(module_obj, self.context, event_name, event_payload)
            return self.call_event(
                module_name=module_name,
                callable_module=listener_callable.__module__,
                callable_name=listener_callable.__name__,
                event_name=event_name,
                event_payload=event_payload,
            )
        _event_proxy.__name__ = listener_callable.__name__
        _event_proxy.__module__ = listener_callable.__module__
        return _event_proxy

    def make_slot_callback(self, module_name, callback_callable):
        def _slot_proxy(context, slot, payload=None):
            _ = context
            if not self.is_remote_module(module_name):
                module_obj = self.context.module_manager.modules[module_name].module
                return callback_callable(module_obj, self.context, slot, payload)
            return self.call_slot(
                module_name=module_name,
                callable_module=callback_callable.__module__,
                callable_name=callback_callable.__name__,
                slot=slot,
                payload=payload,
            )
        _slot_proxy.__name__ = callback_callable.__name__
        _slot_proxy.__module__ = callback_callable.__module__
        return _slot_proxy

    def call_event(self, module_name, callable_module, callable_name, event_name, event_payload):
        if not hasattr(self.context, "runtime_supervisor"):
            raise RuntimeError("Runtime supervisor is not initialized")
        result = self.context.runtime_supervisor.call_event(
            module_name=module_name,
            callable_module=callable_module,
            callable_name=callable_name,
            event_name=event_name,
            event_payload=event_payload,
        )
        return self._unwrap_result_envelope(result)

    def call_slot(self, module_name, callable_module, callable_name, slot, payload=None):
        if not hasattr(self.context, "runtime_supervisor"):
            raise RuntimeError("Runtime supervisor is not initialized")
        result = self.context.runtime_supervisor.call_slot(
            module_name=module_name,
            callable_module=callable_module,
            callable_name=callable_name,
            slot=slot,
            payload=payload,
        )
        return self._unwrap_result_envelope(result)

    def call_module_method(self, module_name, method_name, *args, **kwargs):
        if not self.is_remote_module(module_name):
            target = self.context.module_manager.modules[module_name].module
            return getattr(target, method_name)(*args, **kwargs)
        if not hasattr(self.context, "runtime_supervisor"):
            raise RuntimeError("Runtime supervisor is not initialized")
        result = self.context.runtime_supervisor.call_module_method(
            module_name,
            method_name,
            *args,
            **kwargs,
        )
        return self._unwrap_result_envelope(result)
