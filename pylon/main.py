#!/usr/bin/python3
# coding=utf-8
# pylint: disable=C0411,C0412,C0413

#   Copyright 2020-2025 getcarrier.io
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

"""
    Project entry point
"""

#
# Before all other imports and code: patch standard library and other libraries to use async I/O
#

import os
CORE_WEB_RUNTIME = os.environ.get("PYLON_WEB_RUNTIME", os.environ.get("CORE_WEB_RUNTIME", "flask"))

if CORE_WEB_RUNTIME == "gevent":
    import gevent.monkey  # pylint: disable=E0401
    gevent.monkey.patch_all()
    #
    import psycogreen.gevent  # pylint: disable=E0401
    psycogreen.gevent.patch_psycopg()
    #
    import ssl
    import gevent.hub  # pylint: disable=E0401
    #
    hub_not_errors = list(gevent.hub.Hub.NOT_ERROR)
    hub_not_errors.append(ssl.SSLError)
    gevent.hub.Hub.NOT_ERROR = tuple(hub_not_errors)

#
# Normal imports and code below
#

import uuid
import socket
import signal
import threading
import pkg_resources

import flask  # pylint: disable=E0401
import flask_restful  # pylint: disable=E0401

from pylon.core.tools import log
from pylon.core.tools import log_support
from pylon.core.tools import db_support
from pylon.core.tools import env
from pylon.core.tools import config
from pylon.core.tools import module
from pylon.core.tools import event
from pylon.core.tools import seed
from pylon.core.tools import git
from pylon.core.tools import app
from pylon.core.tools import rpc
from pylon.core.tools import ssl
from pylon.core.tools import slot
from pylon.core.tools import server
from pylon.core.tools import external_routing
from pylon.core.tools import exposure

from pylon.core.tools.dict import recursive_merge
from pylon.core.tools.signal import signal_sigterm
from pylon.core.tools.signal import kill_remaining_processes
from pylon.core.tools.signal import ZombieReaper
from pylon.core.tools.context import Context

from pylon.framework import toolkit


def main():  # pylint: disable=R0912,R0914,R0915
    """ Entry point """
    #
    # Phase: bootstrap
    #
    # Register signal handling early
    signal.signal(signal.SIGTERM, signal_sigterm)
    # Make context holder
    context = Context()
    # Save env-provided settings
    context.web_runtime = CORE_WEB_RUNTIME
    context.runtime_init = env.get_var("INIT", "unknown")
    context.debug = env.get_var("DEVELOPMENT_MODE", "").lower() in ["true", "yes"]
    # Get pylon version
    try:
        context.version = pkg_resources.require("pylon")[0].version
    except:  # pylint: disable=W0702
        context.version = "unknown"
    # Enable basic logging and say hello
    log_support.enable_basic_logging()
    log.info("Starting plugin-based Carrier/Centry core (version %s)", context.version)
    # Load settings from seed
    log.info("Loading and parsing settings")
    context.settings = seed.load_settings()
    if not context.settings:
        log.error("Settings are empty or invalid. Exiting")
        os._exit(1)  # pylint: disable=W0212
    # Basic init
    toolkit.basic_init(context)
    db_support.basic_init(context)
    # Tunable pylon settings
    tunable_settings_data = config.tunable_get("pylon_settings", None)
    if tunable_settings_data is not None:
        log.info("Loading and parsing tunable settings")
        tunable_settings = seed.parse_settings(tunable_settings_data)
        if tunable_settings:
            tunable_settings_mode = tunable_settings.get("pylon", {}).get(
                "tunable_settings_mode", "override"
            )
            if tunable_settings_mode == "merge":
                context.settings = recursive_merge(context.settings, tunable_settings)
            elif tunable_settings_mode == "update":
                context.settings.update(tunable_settings)
            else:
                context.settings = tunable_settings
    # Allow to override debug from config
    if "debug" in context.settings.get("server", {}):
        context.debug = context.settings.get("server").get("debug")
    # Allow to override runtime from config (if initial runtime != gevent)
    if context.web_runtime != "gevent" and "runtime" in context.settings.get("server", {}):
        context.web_runtime = context.settings.get("server").get("runtime")
    # Save reloader status
    context.reloader_used = context.settings.get("server", {}).get(
        "use_reloader",
        env.get_var("USE_RELOADER", "false").lower() in ["true", "yes"],
    )
    context.before_reloader = \
            context.web_runtime == "flask" and \
            context.reloader_used and \
            os.environ.get("WERKZEUG_RUN_MAIN", "false").lower() != "true"
    # Basic de-init in case reloader is used
    if context.before_reloader:
        db_support.basic_deinit(context)
    # Save global node name
    context.node_name = context.settings.get("server", {}).get("name", socket.gethostname())
    # Generate pylon ID
    context.id = f'{context.node_name}_{str(uuid.uuid4())}'
    # Set environment overrides (e.g. to add env var with data from vault)
    log.info("Setting environment overrides")
    for key, value in context.settings.get("environment", {}).items():
        os.environ[key] = value
    # Reinit logging with full config
    log_support.reinit_logging(context)
    # Log pylon ID
    log.info("Pylon ID: %s", context.id)
    # Set process title
    import setproctitle  # pylint: disable=C0415,E0401
    setproctitle.setproctitle(f'pylon {context.id}')
    # Make stop event
    context.stop_event = threading.Event()
    # Initialize local data
    context.local = threading.local()
    # Enable zombie reaping
    if context.settings.get("system", {}).get("zombie_reaping", {}).get("enabled", False):
        context.zombie_reaper = ZombieReaper(context)
        context.zombie_reaper.start()
    # Prepare SSL custom cert bundle
    ssl.init(context)
    # Apply patches needed for pure-python git and providers
    git.apply_patches()
    #
    # Phase: entity instances
    #
    # Make AppManager instance
    log.info("Creating AppManager instance")
    context.app_manager = app.AppManager(context)
    # Make ModuleManager instance
    log.info("Creating ModuleManager instance")
    context.module_manager = module.ModuleManager(context)
    # Make EventManager instance
    log.info("Creating EventManager instance")
    context.event_manager = event.EventManager(context)
    # Make RpcManager instance
    log.info("Creating RpcManager instance")
    context.rpc_manager = rpc.RpcManager(context)
    # Make SlotManager instance
    log.info("Creating SlotManager instance")
    context.slot_manager = slot.SlotManager(context)
    #
    # Phase: A/WSGI apps
    #
    # Add server-related data
    server.init_context(context)
    # Init app hierarchy
    context.app_manager.init_hierarchy()
    #
    # Phase: modules
    #
    # Init framework toolkit
    toolkit.init(context)
    # Initialize DB support
    db_support.init(context)
    # Load and initialize modules
    context.module_manager.init_modules()
    context.event_manager.fire_event("pylon_modules_initialized", context.id)
    #
    # Phase: exposure
    #
    # Register external route
    external_routing.register(context)
    # Expose pylon
    exposure.expose(context)
    #
    # Phase: operational
    #
    # Run A/WSGI server
    try:
        server.run_server(context)
    finally:
        log.info("A/WSGI server stopped")
        # Set stop event
        context.stop_event.set()
        # Unexpose pylon
        exposure.unexpose(context)
        # Unregister external route
        external_routing.unregister(context)
        # De-init modules
        context.module_manager.deinit_modules()
        # De-initialize DB support
        db_support.deinit(context)
    #
    # Phase: terminate
    #
    # Kill remaining processes to avoid keeping the container running on update
    if context.settings.get("system", {}).get("kill_remaining_processes", True) and \
            context.runtime_init in ["pylon", "dumb-init"]:
        kill_remaining_processes(context)
    # Exit
    log.info("Exiting")


if __name__ == "__main__":
    # Call entry point
    main()
