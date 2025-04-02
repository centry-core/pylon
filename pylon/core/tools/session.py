#!/usr/bin/python
# coding=utf-8
# pylint: disable=I0011

#   Copyright 2021 getcarrier.io
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
    Session tools
"""

from flask_session.base import ServerSideSession, ServerSideSessionInterface  # pylint: disable=E0401

from pylon.core.tools import log
from pylon.core.tools.context import Context


def make_session_interface(context):
    """ Make session interface for server-side session storage """
    # Patch
    ServerSideSession.regenerate = _regenerate
    ServerSideSession.destroy = _destroy
    #
    ServerSideSessionInterface.open_session = _patched_open_session(
        ServerSideSessionInterface.open_session
    )
    ServerSideSessionInterface.save_session = _patched_save_session(
        ServerSideSessionInterface.save_session
    )
    # Get configs
    application_config = context.settings.get("application", {})
    sessions_config = context.settings.get("sessions", {})
    #
    session_prefix = sessions_config.get("prefix", None)
    session_permanent = sessions_config.get("permanent", True)
    #
    redis_config = sessions_config.get("redis", {})
    memory_config = sessions_config.get("memory", {})
    # Result
    result = Context()
    # Redis
    if redis_config:
        from redis import StrictRedis  # pylint: disable=E0401,C0415
        from flask_session.redis import RedisSessionInterface  # pylint: disable=E0401,C0415
        #
        client = StrictRedis(
            host=redis_config.get("host", "localhost"),
            port=redis_config.get("port", 6379),
            password=redis_config.get("password", None),
            ssl=redis_config.get("use_ssl", False),
        )
        #
        result.cls = RedisSessionInterface
        result.kwargs = {
            "client": client,
            #
            "use_signer": "SECRET_KEY" in application_config,
            "permanent": session_permanent,
            "sid_length": 32,
            "serialization_format": "msgpack",
        }
        #
        if session_prefix:
            result.kwargs["key_prefix"] = session_prefix
        #
        log.info("Using redis for session storage")
    else:  # Memory
        from cachelib.simple import SimpleCache  # pylint: disable=E0401,C0415
        from flask_session.cachelib import CacheLibSessionInterface  # pylint: disable=E0401,C0415
        #
        client = SimpleCache(
            threshold=memory_config.get("threshold", 1000),
            default_timeout=memory_config.get("default_timeout", 0),
        )
        #
        result.cls = CacheLibSessionInterface
        result.kwargs = {
            "client": client,
            #
            "use_signer": "SECRET_KEY" in application_config,
            "permanent": session_permanent,
            "sid_length": 32,
            "serialization_format": "msgpack",
        }
        #
        if session_prefix:
            result.kwargs["key_prefix"] = session_prefix
        #
        log.info("Using memory for session storage")
    # Done
    return result


def _regenerate(self):
    from flask import current_app  # pylint: disable=E0401,C0415
    current_app.session_interface.regenerate(self)


def _destroy(self):
    from flask import current_app  # pylint: disable=E0401,C0415
    session_interface = current_app.session_interface
    session_interface._delete_session(session_interface._get_store_id(self.sid))  # pylint: disable=W0212
    #
    self.clear()
    self.modified = True


def _patched_open_session(original_open_session):
    def _open_session(self, app, request):
        if isinstance(request, Context):
            if not hasattr(request, "cookies"):
                request.cookies = {}
        #
        return original_open_session(self, app, request)
    #
    return _open_session


def _patched_save_session(original_save_session):
    def _save_session(self, app, session, response):
        if isinstance(response, Context):
            if not hasattr(response, "set_cookie"):
                response.set_cookie = lambda *args, **kwargs: None
            #
            if not hasattr(response, "delete_cookie"):
                response.delete_cookie = lambda *args, **kwargs: None
            #
            if not hasattr(response, "vary"):
                response.vary = set()
        #
        return original_save_session(self, app, session, response)
    #
    return _save_session
