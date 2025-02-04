#!/usr/bin/python
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

# pylint: disable=C0116
""" App compatibility shim """

from pylon.core.tools import log


class AppShimMeta(type):
    """ AppShim meta class """

    def __getattr__(cls, name):
        log.debug("AppShim.cls.__getattr__(%s)", name)
        raise RuntimeError("Not supported")


#
# TODO: save hook_uuids in module descriptor for deinit
#


class AppShim(metaclass=AppShimMeta):  # pylint: disable=R0903
    """ App shim: compatibility proxy adapter """

    def __init__(self, context):
        self.context = context

    def __getattr__(self, name):
        hook_decorators = [
            "errorhandler",
            "template_filter",
        ]
        #
        if name in hook_decorators:
            return self.__make_hook_decorator(name)
        #
        hook_functions = [
            "before_request",
            "after_request",
            "context_processor",
        ]
        #
        if name in hook_functions:
            return self.__make_hook_function(name)
        #
        this_proxies = [
            "app_context",
            "secret_key",
            "session_cookie_name",
            "session_interface",
            "config",
        ]
        #
        if name in this_proxies:
            from tools import this  # pylint: disable=E0401,C0415
            return getattr(this.descriptor.app, name)
        #
        log.debug("AppShim.__getattr__(%s)", name)
        raise RuntimeError("Not supported")

    def __make_hook_function(self, name):
        _name = name
        #
        def _function(*args, **kwargs):
            _args = args
            _kwargs = kwargs
            #
            def _hook(app):
                getattr(app, _name)(*_args, **_kwargs)
            #
            self.context.app_manager.register_app_hook(_hook)
        #
        return _function

    def __make_hook_decorator(self, name):
        _name = name
        #
        def _decorator(*i_args, **i_kwargs):
            _i_args = i_args
            _i_kwargs = i_kwargs
            #
            def _decorate(*j_args, **j_kwargs):
                _j_args = j_args
                _j_kwargs = j_kwargs
                #
                def _hook(app):
                    getattr(app, _name)(*_i_args, **_i_kwargs)(*_j_args, **_j_kwargs)
                #
                self.context.app_manager.register_app_hook(_hook)
            #
            return _decorate
        #
        return _decorator
