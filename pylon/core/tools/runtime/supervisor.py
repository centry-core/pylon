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

""" Runtime supervisor scaffold for grouped plugin processes """

import os
import sys
import json
import time
import signal
import threading
import subprocess

import arbiter  # pylint: disable=E0401

from pylon.core.tools import log


class RuntimeSupervisor:  # pylint: disable=R0902
    """Tracks runtime plan and process-group lifecycle."""

    def __init__(self, context):
        self.context = context
        self.started = False
        self.runtime_plan = None
        self.lock = threading.Lock()
        self.monitor_thread = None
        self.stop_event = threading.Event()
        self.processes = {}  # runtime_group -> subprocess.Popen
        self.restart_history = {}  # runtime_group -> [timestamps]
        self.rpc_event_node = None
        self.rpc_node = None

    def _runtime_settings(self):
        return self.context.settings.get("modules", {}).get("runtime", {})

    def _monitor_interval(self):
        return float(self._runtime_settings().get("monitor_interval", 1.0))

    def _restart_backoff(self):
        return float(self._runtime_settings().get("restart_backoff_sec", 2.0))

    def _restart_window(self):
        return float(self._runtime_settings().get("restart_window_sec", 300.0))

    def _restart_limit(self):
        return int(self._runtime_settings().get("max_restarts", 20))

    def _worker_env(self, runtime_group, group_data):
        worker_env = os.environ.copy()
        module_specs = self._make_module_specs(group_data.get("modules", []))
        worker_spec = {
            "node_id": self.context.id,
            "runtime_group": runtime_group,
            "runtime_mode": group_data.get("mode", "gevent"),
            "restart_policy": group_data.get("restart_policy", "always"),
            "modules": group_data.get("modules", []),
            "module_specs": module_specs,
            "plugins_path": self._get_plugins_path(),
            "rpc_timeout_sec": float(self._runtime_settings().get("call_timeout_sec", 30.0)),
            "zmq": self._make_worker_zmq_config(),
        }
        worker_env["PYLON_RUNTIME_WORKER_SPEC"] = json.dumps(worker_spec)
        return worker_env

    def _get_plugins_path(self):
        modules_settings = self.context.settings.get("modules", {})
        plugins_provider = modules_settings.get("plugins", {}).get("provider", {})
        if plugins_provider.get("type", "") != "folder":
            return None
        return plugins_provider.get("path", None)

    def _make_module_specs(self, module_names):
        result = {}
        module_manager = self.context.module_manager
        for module_name in module_names:
            if module_name not in module_manager.descriptors:
                continue
            descriptor = module_manager.descriptors[module_name]
            loader_path = None
            try:
                loader_path = descriptor.loader.get_local_path()
            except:  # pylint: disable=W0702
                loader_path = None
            result[module_name] = {
                "requirements_path": descriptor.requirements_path,
                "loader_path": loader_path,
                "metadata": {
                    "runtime_group": descriptor.metadata.get("runtime_group", "default"),
                    "runtime_mode": descriptor.metadata.get("runtime_mode", "gevent"),
                    "restart_policy": descriptor.metadata.get("restart_policy", "always"),
                },
            }
        return result

    @staticmethod
    def _normalize_bind_to_connect(addr):
        if not isinstance(addr, str):
            return addr
        if addr.startswith("tcp://*"):
            return addr.replace("tcp://*", "tcp://127.0.0.1", 1)
        if addr.startswith("tcp://0.0.0.0"):
            return addr.replace("tcp://0.0.0.0", "tcp://127.0.0.1", 1)
        return addr

    def _make_worker_zmq_config(self):
        exposure_config = self.context.settings.get("exposure", {})
        zmq_config = exposure_config.get("zmq", {})
        if not zmq_config.get("enabled", False):
            return {"enabled": False}
        bind_pub = zmq_config.get("bind_pub", "tcp://*:5010")
        bind_pull = zmq_config.get("bind_pull", "tcp://*:5011")
        return {
            "enabled": True,
            "connect_sub": self._normalize_bind_to_connect(bind_pub),
            "connect_push": self._normalize_bind_to_connect(bind_pull),
            "topic": zmq_config.get("topic", "events"),
        }

    def _spawn_group(self, runtime_group, group_data):
        modules = group_data.get("modules", [])
        if not modules:
            return
        cmd = [sys.executable, "-m", "pylon.core.tools.runtime.worker"]
        stdio_mode = self._runtime_settings().get("worker_stdio", "null")
        if stdio_mode == "inherit":
            target_stdout = None
            target_stderr = None
        else:
            target_stdout = subprocess.DEVNULL
            target_stderr = subprocess.DEVNULL
        worker_cwd = self._runtime_settings().get("worker_cwd", None)
        process = subprocess.Popen(  # pylint: disable=R1732
            cmd,
            env=self._worker_env(runtime_group, group_data),
            stdout=target_stdout,
            stderr=target_stderr,
            cwd=worker_cwd,
            start_new_session=True,
        )
        self.processes[runtime_group] = process
        log.info(
            "Started runtime worker '%s' (pid=%s, mode=%s, modules=%s)",
            runtime_group,
            process.pid,
            group_data.get("mode", "unknown"),
            ",".join(modules),
        )

    def _worker_ping_name(self, runtime_group):
        return f"runtime_worker_{runtime_group}_ping"

    @staticmethod
    def _worker_module_call_name(runtime_group):
        return f"runtime_worker_{runtime_group}_module_call"

    @staticmethod
    def _worker_route_call_name(runtime_group):
        return f"runtime_worker_{runtime_group}_route_call"

    @staticmethod
    def _worker_event_call_name(runtime_group):
        return f"runtime_worker_{runtime_group}_event_call"

    @staticmethod
    def _worker_slot_call_name(runtime_group):
        return f"runtime_worker_{runtime_group}_slot_call"

    @staticmethod
    def _worker_api_call_name(runtime_group):
        return f"runtime_worker_{runtime_group}_api_call"

    def _wait_group_ready(self, runtime_group):
        startup_timeout = float(self._runtime_settings().get("startup_timeout_sec", 20.0))
        poll_interval = float(self._runtime_settings().get("startup_poll_interval_sec", 0.5))
        elapsed = 0.0
        ping_name = self._worker_ping_name(runtime_group)
        while elapsed <= startup_timeout and not self.stop_event.is_set():
            try:
                if self.rpc_node is None:
                    break
                response = self.rpc_node.call_with_timeout(
                    ping_name,
                    timeout=poll_interval,
                    payload={
                        "source": "runtime-supervisor",
                        "node_id": self.context.id,
                    },
                )
                if isinstance(response, dict) and response.get("ok", False):
                    return True
            except:  # pylint: disable=W0702
                pass
            time.sleep(poll_interval)
            elapsed += poll_interval
        return False

    def _create_rpc_client(self):
        worker_zmq_config = self._make_worker_zmq_config()
        if not worker_zmq_config.get("enabled", False):
            raise RuntimeError("Runtime workers require exposure.zmq.enabled=true")
        self.rpc_event_node = arbiter.make_event_node({
            "type": "ZeroMQEventNode",
            "connect_sub": worker_zmq_config.get("connect_sub", "tcp://127.0.0.1:5010"),
            "connect_push": worker_zmq_config.get("connect_push", "tcp://127.0.0.1:5011"),
            "topic": worker_zmq_config.get("topic", "events"),
        })
        self.rpc_node = arbiter.RpcNode(
            self.rpc_event_node,
            id_prefix=f"runtime_supervisor_{self.context.id}_",
            proxy_timeout=float(self._runtime_settings().get("rpc_timeout_sec", 3.0)),
        )
        self.rpc_event_node.start()
        self.rpc_node.start()

    def _close_rpc_client(self):
        if self.rpc_node is not None:
            try:
                self.rpc_node.stop()
            except:  # pylint: disable=W0702
                pass
        if self.rpc_event_node is not None:
            try:
                self.rpc_event_node.stop()
            except:  # pylint: disable=W0702
                pass
        self.rpc_node = None
        self.rpc_event_node = None

    def _should_restart(self, runtime_group, return_code, restart_policy):
        if self.stop_event.is_set():
            return False
        if restart_policy == "never":
            return False
        if restart_policy == "on-failure" and return_code == 0:
            return False
        now = time.time()
        window = self._restart_window()
        limit = self._restart_limit()
        if runtime_group not in self.restart_history:
            self.restart_history[runtime_group] = []
        recent = [ts for ts in self.restart_history[runtime_group] if now - ts <= window]
        self.restart_history[runtime_group] = recent
        if len(recent) >= limit:
            log.error(
                "Restart limit reached for runtime group '%s' (%s in %.1fs), not restarting",
                runtime_group,
                len(recent),
                window,
            )
            return False
        self.restart_history[runtime_group].append(now)
        return True

    def _monitor_loop(self):
        while not self.stop_event.is_set():
            with self.lock:
                if not self.started or self.runtime_plan is None:
                    return
                groups = self.runtime_plan.get("groups", {})
                for runtime_group, process in list(self.processes.items()):
                    return_code = process.poll()
                    if return_code is None:
                        continue
                    self.processes.pop(runtime_group, None)
                    group_data = groups.get(runtime_group, {})
                    restart_policy = group_data.get("restart_policy", "always")
                    log.warning(
                        "Runtime worker '%s' exited (pid=%s, return_code=%s)",
                        runtime_group,
                        process.pid,
                        return_code,
                    )
                    if self._should_restart(runtime_group, return_code, restart_policy):
                        time.sleep(self._restart_backoff())
                        self._spawn_group(runtime_group, group_data)
                        if not self._wait_group_ready(runtime_group):
                            log.error(
                                "Runtime worker '%s' did not become ready after restart",
                                runtime_group,
                            )
                for runtime_group, group_data in groups.items():
                    if runtime_group not in self.processes:
                        self._spawn_group(runtime_group, group_data)
            self.stop_event.wait(self._monitor_interval())

    def start(self, runtime_plan):
        """Start runtime orchestration using a module runtime plan."""
        with self.lock:
            if self.started:
                return
            self.runtime_plan = runtime_plan
            groups = self.runtime_plan.get("groups", {})
            log.info("Runtime supervisor initialized (%s groups)", len(groups))
            self._create_rpc_client()
            for group_name, group_data in groups.items():
                self._spawn_group(group_name, group_data)
            for group_name in groups:
                if not self._wait_group_ready(group_name):
                    log.error("Runtime worker '%s' did not become ready in time", group_name)
            self.stop_event.clear()
            self.monitor_thread = threading.Thread(
                target=self._monitor_loop,
                name="runtime-supervisor-monitor",
                daemon=True,
            )
            self.monitor_thread.start()
            self.started = True

    def reload(self, runtime_plan):
        """Apply a new runtime plan by restarting workers for changed groups."""
        with self.lock:
            if not self.started:
                self.runtime_plan = runtime_plan
                return
            previous_groups = set(self.runtime_plan.get("groups", {}).keys())
            next_groups = set(runtime_plan.get("groups", {}).keys())
            removed_groups = previous_groups - next_groups
            changed_groups = set()
            for group_name in previous_groups.intersection(next_groups):
                prev_data = self.runtime_plan["groups"][group_name]
                next_data = runtime_plan["groups"][group_name]
                if prev_data != next_data:
                    changed_groups.add(group_name)
            self.runtime_plan = runtime_plan
            for group_name in removed_groups.union(changed_groups):
                self._stop_group(group_name)
            for group_name in next_groups:
                if group_name not in self.processes:
                    self._spawn_group(group_name, self.runtime_plan["groups"][group_name])
                    if not self._wait_group_ready(group_name):
                        log.error("Runtime worker '%s' did not become ready in time", group_name)

    def call_module_method(self, module_name, method_name, *args, **kwargs):
        """Dispatch module method call to the worker owning module runtime group."""
        if self.rpc_node is None:
            raise RuntimeError("Runtime supervisor RPC client is not initialized")
        if self.runtime_plan is None:
            raise RuntimeError("Runtime plan is not initialized")
        runtime_data = self.runtime_plan.get("modules", {}).get(module_name, None)
        if runtime_data is None:
            raise RuntimeError(f"Unknown runtime module: {module_name}")
        runtime_group = runtime_data.get("group", "default")
        timeout = float(self._runtime_settings().get("call_timeout_sec", 30.0))
        return self.rpc_node.call_with_timeout(
            self._worker_module_call_name(runtime_group),
            timeout=timeout,
            module=module_name,
            method=method_name,
            args=list(args),
            kwargs=kwargs,
            source="runtime-shim",
        )

    def call_route(  # pylint: disable=R0913
            self,
            module_name,
            callable_module,
            callable_name,
            module_routes,
            request_data,
        ):
        """Dispatch route function call to the worker owning module runtime group."""
        if self.rpc_node is None:
            raise RuntimeError("Runtime supervisor RPC client is not initialized")
        if self.runtime_plan is None:
            raise RuntimeError("Runtime plan is not initialized")
        runtime_data = self.runtime_plan.get("modules", {}).get(module_name, None)
        if runtime_data is None:
            raise RuntimeError(f"Unknown runtime module: {module_name}")
        runtime_group = runtime_data.get("group", "default")
        timeout = float(self._runtime_settings().get("route_timeout_sec", 30.0))
        return self.rpc_node.call_with_timeout(
            self._worker_route_call_name(runtime_group),
            timeout=timeout,
            module=module_name,
            callable_module=callable_module,
            callable_name=callable_name,
            module_routes=module_routes,
            request_data=request_data,
            source="runtime-route",
        )

    def call_event(self, module_name, callable_module, callable_name, event_name, event_payload):
        """Dispatch event listener call to worker owning module runtime group."""
        if self.rpc_node is None:
            raise RuntimeError("Runtime supervisor RPC client is not initialized")
        if self.runtime_plan is None:
            raise RuntimeError("Runtime plan is not initialized")
        runtime_data = self.runtime_plan.get("modules", {}).get(module_name, None)
        if runtime_data is None:
            raise RuntimeError(f"Unknown runtime module: {module_name}")
        runtime_group = runtime_data.get("group", "default")
        timeout = float(self._runtime_settings().get("event_timeout_sec", 30.0))
        return self.rpc_node.call_with_timeout(
            self._worker_event_call_name(runtime_group),
            timeout=timeout,
            module=module_name,
            callable_module=callable_module,
            callable_name=callable_name,
            event_name=event_name,
            event_payload=event_payload,
            source="runtime-event",
        )

    def call_slot(self, module_name, callable_module, callable_name, slot, payload=None):
        """Dispatch slot callback call to worker owning module runtime group."""
        if self.rpc_node is None:
            raise RuntimeError("Runtime supervisor RPC client is not initialized")
        if self.runtime_plan is None:
            raise RuntimeError("Runtime plan is not initialized")
        runtime_data = self.runtime_plan.get("modules", {}).get(module_name, None)
        if runtime_data is None:
            raise RuntimeError(f"Unknown runtime module: {module_name}")
        runtime_group = runtime_data.get("group", "default")
        timeout = float(self._runtime_settings().get("slot_timeout_sec", 30.0))
        return self.rpc_node.call_with_timeout(
            self._worker_slot_call_name(runtime_group),
            timeout=timeout,
            module=module_name,
            callable_module=callable_module,
            callable_name=callable_name,
            slot=slot,
            payload=payload,
            source="runtime-slot",
        )

    def call_api(  # pylint: disable=R0913
            self,
            module_name,
            api_version,
            resource_name,
            method_name,
            api_kwargs,
            request_data,
        ):
        """Dispatch API resource method call to worker owning module runtime group."""
        if self.rpc_node is None:
            raise RuntimeError("Runtime supervisor RPC client is not initialized")
        if self.runtime_plan is None:
            raise RuntimeError("Runtime plan is not initialized")
        runtime_data = self.runtime_plan.get("modules", {}).get(module_name, None)
        if runtime_data is None:
            raise RuntimeError(f"Unknown runtime module: {module_name}")
        runtime_group = runtime_data.get("group", "default")
        timeout = float(self._runtime_settings().get("api_timeout_sec", 30.0))
        return self.rpc_node.call_with_timeout(
            self._worker_api_call_name(runtime_group),
            timeout=timeout,
            module=module_name,
            api_version=api_version,
            resource_name=resource_name,
            method_name=method_name,
            api_kwargs=api_kwargs,
            request_data=request_data,
            source="runtime-api",
        )

    def _stop_group(self, runtime_group):
        process = self.processes.pop(runtime_group, None)
        if process is None:
            return
        if process.poll() is not None:
            return
        log.info("Stopping runtime worker '%s' (pid=%s)", runtime_group, process.pid)
        process.send_signal(signal.SIGTERM)
        timeout = float(self._runtime_settings().get("stop_timeout_sec", 15.0))
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            log.warning(
                "Runtime worker '%s' did not stop within %.1fs, killing",
                runtime_group,
                timeout,
            )
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    def stop(self):
        """Stop runtime orchestration."""
        with self.lock:
            if not self.started:
                return
            log.info("Stopping runtime supervisor")
            self.stop_event.set()
            for runtime_group in list(self.processes):
                self._stop_group(runtime_group)
            self.started = False
            self._close_rpc_client()
        if self.monitor_thread is not None:
            self.monitor_thread.join(timeout=5)
        self.monitor_thread = None
