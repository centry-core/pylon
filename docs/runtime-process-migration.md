# Runtime Process Mode Migration Guide

This guide documents the runtime process-mode refactor and how to migrate existing Pylon installations and plugins.

## Scope

This migration covers runtime-group execution where plugin modules may run in dedicated worker processes and communicate with the main process through RPC.

## What Changed

### 1. Runtime metadata contract for modules

Module metadata now supports these keys:

- `runtime_group` (default: `default`)
- `runtime_mode` (allowed: `gevent`, `threaded`; default: `gevent`)
- `restart_policy` (default: `always`)

`ModuleManager` normalizes and validates metadata, and builds a runtime plan used by the supervisor.

### 2. Runtime supervisor + worker orchestration

A dedicated runtime supervisor now:

- builds/owns worker process groups
- monitors and restarts workers based on policy
- supports live runtime-plan reload
- dispatches remote calls for:
  - module methods
  - route handlers
  - API resources
  - events
  - slots

### 3. Route/API/event/slot remote forwarding

Main-process registration paths are runtime-aware:

- routes use runtime route proxy wrappers
- API resources use runtime API proxy resources
- event listeners and slot callbacks use runtime callback proxies

When target module is remote, calls are forwarded to the target worker group.

### 4. Direct import shims for remote plugin modules

Runtime import shims are installed for remote modules so direct import usage patterns continue to work:

- `plugins.<module>.module.<callable>(...)`
- `from plugins.<module> import module`

Shims are refreshed on startup and on runtime-plan reload.

### 5. Standardized response/error envelopes across worker RPC handlers

Worker endpoints now return explicit envelopes:

- success: `{"__runtime_envelope__": true, "ok": true, ...}`
- failure: `{"__runtime_envelope__": true, "ok": false, "error": ..., "response": ...}`

Dispatcher unwraps envelopes and preserves HTTP semantics for route/API failures.

### 6. Worker context parity improvements

Worker module context now includes:

- `settings`
- `url_prefix`
- `node_name`, `id`, `runtime_group`
- `event_manager` (local worker manager)
- `slot_manager` (local worker manager)
- `module_manager` with cross-group RPC proxies
- `app` (Flask app reference)
- `tools.context` bootstrap support

## New/Relevant Runtime Settings

Under `modules.runtime`:

- `enabled` (feature switch)
- `local_group`
- `monitor_interval`
- `restart_backoff_sec`
- `restart_window_sec`
- `max_restarts`
- `startup_timeout_sec`
- `startup_poll_interval_sec`
- `stop_timeout_sec`
- `rpc_timeout_sec`
- `call_timeout_sec`
- `route_timeout_sec`
- `api_timeout_sec`
- `event_timeout_sec`
- `slot_timeout_sec`
- `worker_stdio` (`null` or `inherit`)
- `worker_cwd`

Note: workers require `exposure.zmq.enabled: true` for runtime RPC transport.

## Migration Steps

### Step 1: Update module metadata

For each plugin/module that should run in a worker process, set runtime metadata:

```yaml
modules:
  plugins:
    provider:
      type: folder
      path: /path/to/plugins

# module metadata example (location depends on your plugin metadata model)
runtime_group: analytics
runtime_mode: gevent
restart_policy: always
```

Keep same-group modules together if they call each other heavily.

### Step 2: Enable runtime mode and timeouts

Add/adjust runtime settings:

```yaml
modules:
  runtime:
    enabled: true
    local_group: default
    call_timeout_sec: 30
    route_timeout_sec: 30
    api_timeout_sec: 30
    event_timeout_sec: 30
    slot_timeout_sec: 30
    startup_timeout_sec: 20
    stop_timeout_sec: 15
```

### Step 3: Ensure ZeroMQ exposure transport is enabled

```yaml
exposure:
  zmq:
    enabled: true
    bind_pub: tcp://*:5010
    bind_pull: tcp://*:5011
    topic: events
```

### Step 4: Deploy and verify

On startup, verify in logs that:

- runtime supervisor starts
- workers are spawned per group
- workers become ready

Functional checks:

- call one route/API from each remote group
- trigger one event and one slot callback
- validate no missing import errors for direct plugin imports

### Step 5: Roll out safely

Recommended rollout:

1. Move a low-risk module to a non-default `runtime_group`.
2. Validate route/API/event/slot behavior and restart behavior.
3. Migrate additional modules incrementally by group.

## Compatibility Notes

- Existing module-level callable access via `context.module_manager.modules[name].module.method(...)` is preserved; remote calls become RPC-backed.
- Direct remote plugin import usage is supported via runtime import shims.
- Worker slot/event managers are local by design; cross-group callback dispatch is handled via runtime forwarding paths.

## Test Coverage Added

The runtime refactor is validated by these tests:

- `tests/test_runtime_dispatcher.py`
- `tests/test_runtime_worker_lifecycle.py`
- `tests/test_runtime_worker_context.py`
- `tests/test_runtime_forwarding_integration.py`
- `tests/test_runtime_transport_integration.py`

Run:

```bash
PYTHONPATH=/path/to/pylon ./venv/bin/pytest -q \
  tests/test_runtime_dispatcher.py \
  tests/test_runtime_worker_lifecycle.py \
  tests/test_runtime_worker_context.py \
  tests/test_runtime_forwarding_integration.py \
  tests/test_runtime_transport_integration.py
```

## Deferred (Not in this migration)

Operational hardening intentionally deferred:

- advanced worker log aggregation policy
- drain semantics for long-running in-flight calls during restart windows
- additional stress/chaos scenarios
