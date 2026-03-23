#!/usr/bin/python
# coding=utf-8
# pyright: reportMissingImports=false

import sys
import types
from types import SimpleNamespace

import flask
import flask_restful


def _install_centry_stubs():
    if "centry_logging" in sys.modules:
        return
    log_stub = SimpleNamespace(
        exception=lambda *args, **kwargs: None,
        info=lambda *args, **kwargs: None,
        warning=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
        debug=lambda *args, **kwargs: None,
    )
    centry_logging = types.ModuleType("centry_logging")
    centry_logging.log = log_stub
    tools_debug = types.ModuleType("centry_logging.tools.debug")
    filters_string = types.ModuleType("centry_logging.filters.string")
    tools_debug.DebugLogStream = object
    filters_string.StringFilter = object
    sys.modules["centry_logging"] = centry_logging
    sys.modules["centry_logging.tools"] = types.ModuleType("centry_logging.tools")
    sys.modules["centry_logging.tools.debug"] = tools_debug
    sys.modules["centry_logging.filters"] = types.ModuleType("centry_logging.filters")
    sys.modules["centry_logging.filters.string"] = filters_string


def _install_arbiter_stubs():
    if "arbiter" in sys.modules:
        return
    arbiter_mod = types.ModuleType("arbiter")
    arbiter_mod.ZeroMQEventNode = object
    arbiter_mod.RpcNode = object
    arbiter_mod.MockEventNode = object
    sys.modules["arbiter"] = arbiter_mod


_install_centry_stubs()
_install_arbiter_stubs()

from pylon.core.tools.runtime.dispatcher import RuntimeDispatcher


class FakeSupervisor:
    def __init__(self):
        self.route_calls = []
        self.api_calls = []
        self.event_calls = []
        self.slot_calls = []

    def call_route(self, **kwargs):
        self.route_calls.append(kwargs)
        return {
            "body": b"route-ok",
            "status": 202,
            "headers": [("Content-Type", "text/plain")],
        }

    def call_api(self, **kwargs):
        self.api_calls.append(kwargs)
        return {
            "body": b'{"ok": true}',
            "status": 207,
            "headers": [("Content-Type", "application/json")],
        }

    def call_event(self, **kwargs):
        self.event_calls.append(kwargs)
        return "event-ok"

    def call_slot(self, **kwargs):
        self.slot_calls.append(kwargs)
        return "slot-ok"


def _make_context():
    module_manager = SimpleNamespace(
        runtime_modules={
            "remote_module": {
                "group": "group_b",
                "mode": "threaded",
                "restart_policy": "always",
            }
        },
        descriptors={},
        modules={
            "remote_module": SimpleNamespace(module=SimpleNamespace()),
        },
    )
    return SimpleNamespace(
        settings={
            "modules": {
                "runtime": {
                    "enabled": True,
                    "local_group": "default",
                }
            }
        },
        module_manager=module_manager,
        runtime_supervisor=FakeSupervisor(),
    )


def test_remote_route_proxy_forwards_request_context_and_route_kwargs():
    context = _make_context()
    dispatcher = RuntimeDispatcher(context)
    app = flask.Flask(__name__)

    def route_handler(module, item_id):
        _ = module
        return f"local-{item_id}"

    proxy = dispatcher.make_route_view("remote_module", route_handler, module_routes=True)

    with app.test_request_context(
        "/plugins/demo/42?x=1",
        method="POST",
        headers={"X-Test": "1"},
        data=b"payload",
        content_type="text/plain",
    ):
        response = proxy(item_id="42")

    assert response.status_code == 202
    assert response.get_data() == b"route-ok"
    forwarded = context.runtime_supervisor.route_calls[0]
    assert forwarded["module_name"] == "remote_module"
    assert forwarded["callable_name"] == "route_handler"
    assert forwarded["request_data"]["method"] == "POST"
    assert forwarded["request_data"]["query_string"] == b"x=1"
    assert forwarded["request_data"]["route_kwargs"] == {"item_id": "42"}
    assert forwarded["request_data"]["body"] == b"payload"


def test_remote_api_proxy_resource_forwards_request_context_and_api_kwargs():
    context = _make_context()
    dispatcher = RuntimeDispatcher(context)
    app = flask.Flask(__name__)
    api = flask_restful.Api(app)

    resource_cls = dispatcher.make_api_resource("remote_module", "v1", "demo")
    api.add_resource(resource_cls, "/api/v1/demo/<item_id>")

    client = app.test_client()
    response = client.patch(
        "/api/v1/demo/99?debug=1",
        headers={"X-Api": "1"},
        data=b'{"k":1}',
        content_type="application/json",
    )

    assert response.status_code == 207
    assert response.get_data() == b'{"ok": true}'
    forwarded = context.runtime_supervisor.api_calls[0]
    assert forwarded["module_name"] == "remote_module"
    assert forwarded["api_version"] == "v1"
    assert forwarded["resource_name"] == "demo"
    assert forwarded["method_name"] == "patch"
    assert forwarded["api_kwargs"] == {"item_id": "99"}
    assert forwarded["request_data"]["method"] == "PATCH"
    assert forwarded["request_data"]["query_string"] == b"debug=1"


def test_remote_event_and_slot_proxies_forward_calls():
    context = _make_context()
    dispatcher = RuntimeDispatcher(context)

    def event_handler(module, ctx, event_name, payload):
        _ = module, ctx, event_name, payload
        return "local-event"

    def slot_handler(module, ctx, slot, payload):
        _ = module, ctx, slot, payload
        return "local-slot"

    event_proxy = dispatcher.make_event_listener("remote_module", event_handler)
    slot_proxy = dispatcher.make_slot_callback("remote_module", slot_handler)

    event_result = event_proxy(context, "build.done", {"ok": True})
    slot_result = slot_proxy(context, "sidebar", {"x": 1})

    assert event_result == "event-ok"
    assert slot_result == "slot-ok"
    assert context.runtime_supervisor.event_calls[0]["event_name"] == "build.done"
    assert context.runtime_supervisor.slot_calls[0]["slot"] == "sidebar"
