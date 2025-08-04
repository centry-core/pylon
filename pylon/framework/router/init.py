#!/usr/bin/python3
# coding=utf-8
# pylint: disable=C0415

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

""" Toolkit """

from pylon.core.tools import log


def init(context):
    """ Init """
    # Config
    framework_config = context.settings.get("framework", {})
    # Router
    router_config = framework_config.get("router", {})
    #
    if router_config.get("enabled", True):
        log.info("Creating router instance")
        #
        router_app = context.app_manager.make_app_instance("pylon.framework.router")
        #
        # Register routes
        #
        context.app_router.map["/"] = router_app
