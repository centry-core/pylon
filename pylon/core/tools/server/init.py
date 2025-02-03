#!/usr/bin/python3
# coding=utf-8

#   Copyright 2025 getcarrier.io
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

""" Server """

import os
import signal
import logging
import importlib
import subprocess

from pylon.core.tools import log


def init_context(context):
    """ Add server-related data to context """
    context.url_prefix = context.settings.get("server", {}).get("path", "/")
    while context.url_prefix.endswith("/"):
        context.url_prefix = context.url_prefix[:-1]
    #
    context.is_async = context.web_runtime in ["hypercorn"]
    if context.is_async:
        # Mute "Task exception was never retrieved"
        logging.getLogger("asyncio").setLevel(logging.CRITICAL)
    #
    context.server_log_filter = log.Filter()
    logging.getLogger("server").addFilter(context.server_log_filter)
    logging.getLogger("werkzeug").addFilter(context.server_log_filter)
    logging.getLogger("geventwebsocket.handler").addFilter(context.server_log_filter)


def run_server(context):
    """ Run A/WSGI server """
    log.info("Starting %s server", context.web_runtime)
    #
    runtime = importlib.import_module(f"pylon.core.tools.server.{context.web_runtime}")
    runtime.run_server(context)


def restart():
    """ Stop server (will be restarted by docker/runtime) """
    from tools import context  # pylint: disable = E0401,C0415
    #
    pylon_pid = os.getpid()
    if context.runtime_init == "dumb-init":
        pylon_pid = 1
    #
    restart_method = context.settings.get("server", {}).get("restart_method", "subprocess")
    #
    log.info("Stopping for a restart (pid = %s, method = %s)", pylon_pid, restart_method)
    #
    if restart_method == "subprocess":
        subprocess.Popen(  # pylint: disable=R1732
            ["/bin/bash", "-c", f"bash -c 'sleep 1; kill {pylon_pid}' &"]
        )
    else:
        os.kill(pylon_pid, signal.SIGTERM)
