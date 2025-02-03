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

from pylon.core import constants


def run_server(context):
    """ Run A/WSGI server """
    import asyncio  # pylint: disable=E0401,C0412,C0415
    import uvicorn  # pylint: disable=E0401,C0412,C0415
    #
    async def _server():
        config = uvicorn.Config(
            context.root_router,
            host=context.settings.get("server", {}).get("host", constants.SERVER_DEFAULT_HOST),
            port=context.settings.get("server", {}).get("port", constants.SERVER_DEFAULT_PORT),
            log_level="critical",
            **context.settings.get("server", {}).get("kwargs", {}),
        )
        server = uvicorn.Server(config)
        #
        await server.serve()
    #
    asyncio.run(
        _server(),
    )
