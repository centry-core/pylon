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

import threading

import socketio  # pylint: disable=E0401

from pylon.core.tools import log
from pylon.core.tools import db_support


def create_socketio_instance(context):  # pylint: disable=R0914,R0912,R0915
    """ Create SocketIO instance """
    client_manager = create_client_manager(context)
    socketio_config = context.settings.get("socketio", {})
    #
    sio_kwargs = {}
    for arg_item in ["transports"]:
        if arg_item in socketio_config:
            sio_kwargs[arg_item] = socketio_config[arg_item]
    #
    if context.web_runtime == "gevent":
        context.sio = SIOPatchedServer(
            async_mode="gevent",
            client_manager=client_manager,
            cors_allowed_origins=socketio_config.get("cors_allowed_origins", "*"),
            **sio_kwargs,
        )
    elif context.web_runtime == "hypercorn":
        context.sio_async = SIOPatchedAsyncServer(
            async_mode="asgi",
            client_manager=client_manager,
            cors_allowed_origins=socketio_config.get("cors_allowed_origins", "*"),
            **sio_kwargs,
        )
        context.sio = SIOAsyncProxy(context)
    elif context.web_runtime == "waitress":
        context.sio = SIOPatchedServer(
            allow_upgrades=True,
            async_mode="threading",
            client_manager=client_manager,
            cors_allowed_origins=socketio_config.get("cors_allowed_origins", "*"),
            **sio_kwargs,
        )
    else:  # flask
        context.sio = SIOPatchedServer(
            async_mode="threading",
            client_manager=client_manager,
            cors_allowed_origins=socketio_config.get("cors_allowed_origins", "*"),
            **sio_kwargs,
        )


def create_client_manager(context):
    """ Make client_manager instance """
    client_manager = None
    #
    socketio_config = context.settings.get("socketio", {})
    socketio_rabbitmq = socketio_config.get("rabbitmq", {})
    socketio_redis = socketio_config.get("redis", {})
    #
    if socketio_rabbitmq:
        try:
            host = socketio_rabbitmq.get("host")
            port = socketio_rabbitmq.get("port", 5672)
            user = socketio_rabbitmq.get("user", "")
            password = socketio_rabbitmq.get("password", "")
            vhost = socketio_rabbitmq.get("vhost", "carrier")
            queue = socketio_rabbitmq.get("queue", "socketio")
            #
            url = f'ampq://{user}:{password}@{host}:{port}/{vhost}'
            #
            if context.is_async:
                client_manager = socketio.AsyncAioPikaManager(
                    url=url, channel=queue,
                )
            else:
                client_manager = socketio.KombuManager(
                    url=url, channel=queue,
                )
        except:  # pylint: disable=W0702
            log.exception("Cannot make KombuManager instance, SocketIO is in standalone mode")
    #
    if socketio_redis:
        try:
            host = socketio_redis.get("host")
            port = socketio_redis.get("port", 6379)
            password = socketio_redis.get("password", "")
            database = socketio_redis.get("database", 0)
            queue = socketio_redis.get("queue", "socketio")
            use_ssl = socketio_redis.get("use_ssl", False)
            #
            if password is None:
                password = ""
            #
            scheme = "rediss" if use_ssl else "redis"
            url = f'{scheme}://:{password}@{host}:{port}/{database}'
            #
            if context.is_async:
                client_manager = socketio.AsyncRedisManager(
                    url=url, channel=queue,
                )
            else:
                client_manager = socketio.RedisManager(
                    url=url, channel=queue,
                )
        except:  # pylint: disable=W0702
            log.exception("Cannot make RedisManager instance, SocketIO is in standalone mode")
    #
    return client_manager


class SIOEventHandler:
    """ Pylon SocketIO Event handler """

    def __init__(self):
        self.handlers = []

    def __call__(self, *args, **kwargs):
        """ Call handler """
        for handler in self.handlers:
            try:
                handler(*args, **kwargs)
            except:  # pylint: disable=W0702
                log.exception("Failed to run SIO event handler '%s', skipping", handler)


class SIOPatchedServer(socketio.Server):  # pylint: disable=R0903
    """ SockerIO Server patched for Pylon """

    def __init__(self, *args, **kwargs):
        self.pylon_emit_lock = threading.Lock()
        self.pylon_any_handlers = []
        self.pylon_event_handlers = {}
        #
        super().__init__(*args, **kwargs)

    def emit(self, *args, **kwargs):
        """ Lock and emit() """
        with self.pylon_emit_lock:
            return super().emit(*args, **kwargs)

    def on(self, event, handler=None, namespace=None):
        """ Register an event handler """
        namespace = namespace or '/'
        #
        def _on(handler):
            #
            # Pylon part
            #
            if namespace not in self.pylon_event_handlers:
                self.pylon_event_handlers[namespace] = {}
            #
            if event not in self.pylon_event_handlers[namespace]:
                self.pylon_event_handlers[namespace][event] = SIOEventHandler()
            #
            if handler not in self.pylon_event_handlers[namespace][event].handlers:
                self.pylon_event_handlers[namespace][event].handlers.append(handler)
            #
            # SIO part
            #
            if namespace not in self.handlers:
                self.handlers[namespace] = {}
            #
            if event not in self.handlers[namespace]:
                self.handlers[namespace][event] = self.pylon_event_handlers[namespace][event]
            #
            return handler
        #
        if handler is None:
            return _on
        #
        _on(handler)

    def remove_handler(self, event, handler, namespace=None):
        """ Remove handler """
        namespace = namespace or "/"
        #
        if namespace not in self.handlers:
            return
        #
        if event not in self.handlers[namespace]:
            return
        #
        if handler not in self.handlers[namespace][event].handlers:
            return
        #
        self.handlers[namespace][event].handlers.remove(handler)

    def _trigger_event(self, event, namespace, *args):
        """ Call *any* handlers first """
        db_support.create_local_session()
        try:
            for any_handler in self.pylon_any_handlers:
                try:
                    any_handler(event, namespace, args)
                except:  # pylint: disable=W0702
                    log.exception("Failed to run SIO *any* handler, skipping")
            #
            return super()._trigger_event(event, namespace, *args)
        finally:
            db_support.close_local_session()

    def pylon_trigger_event(self, event, namespace, *args):
        """ Call original handlers """
        return super()._trigger_event(event, namespace, *args)

    def pylon_add_any_handler(self, handler):
        """ Add *any* handler """
        if handler in self.pylon_any_handlers:
            return
        #
        self.pylon_any_handlers.append(handler)

    def pylon_remove_any_handler(self, handler):
        """ Remove *any* handler """
        if handler not in self.pylon_any_handlers:
            return
        #
        self.pylon_any_handlers.remove(handler)


class SIOAsyncEventHandler:
    """ Pylon SocketIO Async Event handler """

    def __init__(self):
        self.handlers = []

    async def __call__(self, *args, **kwargs):
        """ Call handler """
        import asyncio  # pylint: disable=E0401,C0412,C0415
        #
        for handler in self.handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(*args, **kwargs)
                else:
                    handler(*args, **kwargs)
            except:  # pylint: disable=W0702
                log.exception("Failed to run SIO event handler '%s', skipping", handler)


class SIOPatchedAsyncServer(socketio.AsyncServer):  # pylint: disable=R0903
    """ SockerIO AsyncServer patched for Pylon """

    def __init__(self, *args, **kwargs):
        self.pylon_any_handlers = []  # 'public', expected to be used by proxy
        self.pylon_event_handlers = {}
        #
        super().__init__(*args, **kwargs)

    def on(self, event, handler=None, namespace=None):
        """ Register an event handler """
        namespace = namespace or '/'
        #
        def _on(handler):
            #
            # Pylon part
            #
            if namespace not in self.pylon_event_handlers:
                self.pylon_event_handlers[namespace] = {}
            #
            if event not in self.pylon_event_handlers[namespace]:
                self.pylon_event_handlers[namespace][event] = SIOAsyncEventHandler()
            #
            if handler not in self.pylon_event_handlers[namespace][event].handlers:
                self.pylon_event_handlers[namespace][event].handlers.append(handler)
            #
            # SIO part
            #
            if namespace not in self.handlers:
                self.handlers[namespace] = {}
            #
            if event not in self.handlers[namespace]:
                self.handlers[namespace][event] = self.pylon_event_handlers[namespace][event]
            #
            return handler
        #
        if handler is None:
            return _on
        #
        _on(handler)

    def remove_handler(self, event, handler, namespace=None):
        """ Remove handler """
        namespace = namespace or "/"
        #
        if namespace not in self.handlers:
            return
        #
        if event not in self.handlers[namespace]:
            return
        #
        if handler not in self.handlers[namespace][event].handlers:
            return
        #
        self.handlers[namespace][event].handlers.remove(handler)

    async def _trigger_event(self, event, namespace, *args):
        """ Call *any* handlers first """
        import asyncio  # pylint: disable=E0401,C0412,C0415
        #
        db_support.create_local_session()
        try:
            for any_handler in self.pylon_any_handlers:
                try:
                    if asyncio.iscoroutinefunction(any_handler):
                        await any_handler(event, namespace, args)
                    else:
                        any_handler(event, namespace, args)
                except:  # pylint: disable=W0702
                    log.exception("Failed to run SIO *any* handler, skipping")
            #
            return await super()._trigger_event(event, namespace, *args)
        finally:
            db_support.close_local_session()

    async def pylon_trigger_event(self, event, namespace, *args):
        """ Call original handlers """
        return await super()._trigger_event(event, namespace, *args)


class SIOAsyncProxy:  # pylint: disable=R0903
    """ Sync proxy to SockerIO AsyncServer """

    def __init__(self, context):
        self.context = context
        #
        self._emit_lock = threading.Lock()
        self._any_async_handlers = {}  # handler -> async version
        #
        import asgiref.sync  # pylint: disable=E0401,C0412,C0415
        self.__sync_emit = asgiref.sync.AsyncToSync(
            self.context.sio_async.emit
        )
        self.__sync_trigger_event = asgiref.sync.AsyncToSync(
            self.context.sio_async.pylon_trigger_event
        )
        self.__sync_enter_room = asgiref.sync.AsyncToSync(
            self.context.sio_async.enter_room
        )
        self.__sync_leave_room = asgiref.sync.AsyncToSync(
            self.context.sio_async.leave_room
        )

    @staticmethod
    def _in_async():
        try:
            import asyncio  # pylint: disable=E0401,C0412,C0415
            event_loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            if event_loop.is_running():
                return True
        #
        return False

    def __getattr__(self, name):
        if self._in_async():
            if hasattr(self, f"_async_{name}"):
                return getattr(self, f"_async_{name}")
        elif hasattr(self, f"_sync_{name}"):
            return getattr(self, f"_sync_{name}")
        #
        log.warning("[SIOAsyncProxy NotImplemented] %s", name)
        raise AttributeError

    def on(self, event, handler=None, namespace=None):
        """ Proxy method """
        return self.context.sio_async.on(event, handler, namespace)

    def remove_handler(self, event, handler, namespace=None):
        """ Proxy method """
        return self.context.sio_async.remove_handler(event, handler, namespace)

    async def _async_emit(self, *args, **kwargs):
        """ Proxy method """
        return await self.context.sio_async.emit(*args, **kwargs)

    def _sync_emit(self, *args, **kwargs):
        """ Proxy method """
        with self._emit_lock:
            return self.__sync_emit(*args, **kwargs)

    def enter_room(self, *args, **kwargs):
        """ Proxy method """
        return self.__sync_enter_room(*args, **kwargs)

    def leave_room(self, *args, **kwargs):
        """ Proxy method """
        return self.__sync_leave_room(*args, **kwargs)

    def pylon_trigger_event(self, event, namespace, *args):
        """ Call original handlers """
        return self.__sync_trigger_event(event, namespace, *args)

    def pylon_add_any_handler(self, handler):
        """ Add *any* handler """
        if handler in self._any_async_handlers:
            return
        #
        import asgiref.sync  # pylint: disable=E0401,C0412,C0415
        async_handler = asgiref.sync.SyncToAsync(handler)
        #
        self._any_async_handlers[handler] = async_handler
        self.context.sio_async.pylon_any_handlers.append(async_handler)

    def pylon_remove_any_handler(self, handler):
        """ Remove *any* handler """
        if handler not in self._any_async_handlers:
            return
        #
        async_handler = self._any_async_handlers.pop(handler)
        self.context.sio_async.pylon_any_handlers.remove(async_handler)
