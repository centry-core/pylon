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

""" Runtime worker process bootstrap """

import os
import json
import signal
import threading

import arbiter  # pylint: disable=E0401

from pylon.core.tools import log


def _load_worker_spec():
    raw_data = os.environ.get("PYLON_RUNTIME_WORKER_SPEC", "")
    if not raw_data:
        raise RuntimeError("Missing PYLON_RUNTIME_WORKER_SPEC")
    return json.loads(raw_data)


def _make_event_node(zmq_config):
    if not zmq_config.get("enabled", False):
        return arbiter.MockEventNode()
    return arbiter.ZeroMQEventNode(
        connect_sub=zmq_config.get("connect_sub", "tcp://127.0.0.1:5010"),
        connect_push=zmq_config.get("connect_push", "tcp://127.0.0.1:5011"),
        topic=zmq_config.get("topic", "events"),
    )


def run_worker():
    """Runtime worker process entrypoint."""
    worker_spec = _load_worker_spec()
    runtime_group = worker_spec.get("runtime_group", "unknown")
    runtime_mode = worker_spec.get("runtime_mode", "gevent")
    modules = worker_spec.get("modules", [])
    stop_event = threading.Event()

    def _sigterm_handler(_signal_num, _stack_frame):
        stop_event.set()

    signal.signal(signal.SIGTERM, _sigterm_handler)
    signal.signal(signal.SIGINT, _sigterm_handler)

    log.info(
        "Runtime worker started [group=%s, mode=%s, modules=%s]",
        runtime_group,
        runtime_mode,
        ",".join(modules),
    )

    event_node = _make_event_node(worker_spec.get("zmq", {}))
    rpc_node = arbiter.RpcNode(
        event_node,
        id_prefix=f"runtime_worker_{runtime_group}_",
    )
    event_node.start()
    rpc_node.start()

    try:
        while not stop_event.wait(1.0):
            pass
    finally:
        rpc_node.stop()
        event_node.stop()
        log.info("Runtime worker stopped [group=%s]", runtime_group)


def main():
    """CLI entrypoint for worker process."""
    try:
        run_worker()
    except SystemExit:
        raise
    except:  # pylint: disable=W0702
        log.exception("Runtime worker crashed")
        raise


if __name__ == "__main__":
    main()
