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
        worker_spec = {
            "node_id": self.context.id,
            "runtime_group": runtime_group,
            "runtime_mode": group_data.get("mode", "gevent"),
            "restart_policy": group_data.get("restart_policy", "always"),
            "modules": group_data.get("modules", []),
            "zmq": self._make_worker_zmq_config(),
        }
        worker_env["PYLON_RUNTIME_WORKER_SPEC"] = json.dumps(worker_spec)
        return worker_env

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
        process = subprocess.Popen(  # pylint: disable=R1732
            cmd,
            env=self._worker_env(runtime_group, group_data),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
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
            for group_name, group_data in groups.items():
                self._spawn_group(group_name, group_data)
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
        if self.monitor_thread is not None:
            self.monitor_thread.join(timeout=5)
        self.monitor_thread = None
