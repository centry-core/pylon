#!/usr/bin/python
# coding=utf-8

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


class RuntimeDispatcher:  # pylint: disable=R0903
    """Resolves local vs remote module execution and creates call shims."""

    def __init__(self, context):
        self.context = context

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

    def call_module_method(self, module_name, method_name, *args, **kwargs):
        if not self.is_remote_module(module_name):
            target = self.context.module_manager.modules[module_name].module
            return getattr(target, method_name)(*args, **kwargs)
        if not hasattr(self.context, "runtime_supervisor"):
            raise RuntimeError("Runtime supervisor is not initialized")
        return self.context.runtime_supervisor.call_module_method(
            module_name,
            method_name,
            *args,
            **kwargs,
        )
