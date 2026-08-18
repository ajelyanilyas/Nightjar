"""The web layer: a JSON API plus the single-page dashboard.

Detection is cheap for demo-sized logs, so the API simply re-runs the pipeline
and caches the result until something changes it (e.g. the /api/replay button
regenerates the scenario). The dashboard polls /api/summary for a live feel.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from ..pipeline import DetectionResult, run_detection
from ..replay import SCENARIOS, generate_scenario

_STATIC = Path(__file__).parent / "static"


def create_app(logs_dir: str = "data", rules_dir: str = "rules") -> FastAPI:
    app = FastAPI(title="Nightjar", description="Detection-as-Code mini-SIEM")
    state: dict[str, object] = {"logs": logs_dir, "rules": rules_dir, "cache": None}

    def result() -> DetectionResult:
        if state["cache"] is None:
            state["cache"] = run_detection(state["logs"], state["rules"])
        return state["cache"]  # type: ignore[return-value]

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "logs": str(state["logs"]), "rules": str(state["rules"])}

    @app.get("/api/summary")
    def summary() -> JSONResponse:
        try:
            return JSONResponse(result().summary())
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    @app.get("/api/alerts")
    def alerts(limit: int = 100, severity: str | None = None) -> JSONResponse:
        items = result().alerts
        if severity:
            items = [a for a in items if a.severity == severity.lower()]
        return JSONResponse([a.to_dict() for a in items[:limit]])

    @app.get("/api/rules")
    def rules() -> JSONResponse:
        return JSONResponse([
            {
                "id": r.id, "title": r.title, "severity": r.severity,
                "mitre": r.mitre, "description": r.description.strip(),
                "correlation": bool(r.correlation),
            }
            for r in result().rules
        ])

    @app.post("/api/replay")
    def replay(scenario: str = "full") -> JSONResponse:
        if scenario not in SCENARIOS:
            raise HTTPException(status_code=400, detail=f"unknown scenario {scenario!r}")
        counts = generate_scenario(state["logs"], scenario)
        state["cache"] = None  # force re-detection on next read
        res = result()
        return JSONResponse({
            "generated": counts,
            "alerts": res.summary()["total_alerts"],
        })

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(_STATIC / "index.html")

    return app
