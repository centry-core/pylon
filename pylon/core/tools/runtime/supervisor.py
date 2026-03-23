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

from pylon.core.tools import log


class RuntimeSupervisor:  # pylint: disable=R0902
    """Tracks runtime plan and process-group lifecycle.

    This initial implementation is intentionally non-disruptive and only
    builds/stores process-group plans. Actual child-process lifecycle management
    is introduced in later iterations.
    """

    def __init__(self, context):
        self.context = context
        self.started = False
        self.runtime_plan = None

    def start(self, runtime_plan):
        """Start runtime orchestration using a module runtime plan."""
        if self.started:
            return
        self.runtime_plan = runtime_plan
        groups = self.runtime_plan.get("groups", {})
        log.info("Runtime supervisor initialized (%s groups)", len(groups))
        for group_name, group_data in groups.items():
            log.info(
                "Runtime group prepared: %s [mode=%s, restart=%s, modules=%s]",
                group_name,
                group_data.get("mode", "unknown"),
                group_data.get("restart_policy", "always"),
                ",".join(group_data.get("modules", [])),
            )
        self.started = True

    def stop(self):
        """Stop runtime orchestration."""
        if not self.started:
            return
        log.info("Stopping runtime supervisor")
        self.started = False
