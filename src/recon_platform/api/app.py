"""FastAPI application factory.

Exposes the platform over HTTP + WebSocket:

* ``POST /runs``            start a recon run (returns a run id immediately)
* ``GET  /runs/{id}``       fetch a completed run's report bundle (JSON)
* ``GET  /runs/{id}/report?format=markdown|html|json``  rendered report
* ``GET  /tools``           the MCP tool catalogue
* ``WS   /ws/{id}``         live event stream for a run (agent activity)
* ``GET  /healthz``         liveness

FastAPI is an optional extra (``pip install '.[api]'``); the factory imports it
lazily so the rest of the platform works without it.
"""

from __future__ import annotations

import asyncio
from typing import Any

from recon_platform.bootstrap import build_container
from recon_platform.core.container import Container
from recon_platform.domain.enums import WorkflowType
from recon_platform.domain.interfaces import ToolRegistry
from recon_platform.domain.schemas import EngagementContext
from recon_platform.orchestration.graph import ReconOrchestrator
from recon_platform.reporting.renderers import get_renderer


def create_app(container: Container | None = None):  # noqa: C901 - factory
    from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
    from pydantic import BaseModel

    container = container or build_container()
    app = FastAPI(title="recon-platform", version="0.2.0")

    # In-memory run registry (swap for Redis/Postgres in the infra config).
    runs: dict[str, dict[str, Any]] = {}
    orchestrators: dict[str, ReconOrchestrator] = {}

    class RunRequest(BaseModel):
        target: str
        workflow: WorkflowType = WorkflowType.PASSIVE_RECON
        # Opt-in browser agent (requires the 'browser' extra; degrades to a
        # no-op when Playwright is unavailable).
        browser: bool = False

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/tools")
    async def tools() -> list[dict[str, Any]]:
        registry = container.resolve(ToolRegistry)  # type: ignore[type-abstract]
        return registry.describe()  # type: ignore[attr-defined]

    @app.post("/runs")
    async def start_run(req: RunRequest) -> dict[str, str]:
        # Each run gets its own orchestrator (fresh graph/memory) via a fresh
        # container, so concurrent runs don't share state. An explicit Settings
        # is used only when the browser agent is requested for this run.
        if req.browser:
            from recon_platform.core.config import Settings

            run_settings = Settings()
            run_settings.browser.enabled = True
            run_container = build_container(run_settings)
        else:
            run_container = build_container()
        orch = ReconOrchestrator(run_container)
        engagement = EngagementContext(target=req.target, workflow=req.workflow)
        runs[engagement.id] = {"status": "running", "bundle": None}
        orchestrators[engagement.id] = orch

        async def _run() -> None:
            try:
                bundle = await orch.run(engagement)
                runs[engagement.id] = {"status": "completed", "bundle": bundle}
            except Exception as exc:  # noqa: BLE001
                runs[engagement.id] = {"status": "failed", "error": str(exc)}

        asyncio.create_task(_run())
        return {"run_id": engagement.id, "status": "running"}

    @app.get("/runs/{run_id}")
    async def get_run(run_id: str) -> dict[str, Any]:
        if run_id not in runs:
            raise HTTPException(404, "unknown run")
        rec = runs[run_id]
        bundle = rec.get("bundle")
        return {
            "run_id": run_id,
            "status": rec["status"],
            "report": bundle.model_dump(mode="json") if bundle else None,
            "error": rec.get("error"),
        }

    @app.get("/runs/{run_id}/report")
    async def get_report(run_id: str, format: str = "markdown") -> Any:
        from fastapi.responses import PlainTextResponse

        rec = runs.get(run_id)
        if not rec or not rec.get("bundle"):
            raise HTTPException(404, "report not ready")
        rendered = get_renderer(format).render(rec["bundle"])
        media = {"html": "text/html", "json": "application/json"}.get(format, "text/markdown")
        return PlainTextResponse(rendered, media_type=media)

    @app.websocket("/ws/{run_id}")
    async def ws(websocket: WebSocket, run_id: str) -> None:
        await websocket.accept()
        orch = orchestrators.get(run_id)
        if orch is None:
            await websocket.send_json({"event": "error", "detail": "unknown run"})
            await websocket.close()
            return
        try:
            async for event in orch.stream_events():
                await websocket.send_json(event)
        except WebSocketDisconnect:
            return

    return app
