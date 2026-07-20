"""Flask dashboard for live WIDS alerts and inventory."""

from __future__ import annotations

import json
import queue
import threading
import time
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

from ..alerts.alert import Alert
from ..alerts.store import EventStore
from ..config import PROJECT_ROOT

TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


def create_app(store: EventStore) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(TEMPLATE_DIR),
        static_folder=str(STATIC_DIR),
    )
    app.config["STORE"] = store

    clients: list[queue.Queue] = []
    clients_lock = threading.Lock()

    def _on_alert(alert: Alert) -> None:
        payload = json.dumps(alert.to_dict())
        with clients_lock:
            dead = []
            for q in clients:
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                try:
                    clients.remove(q)
                except ValueError:
                    pass

    store.add_listener(_on_alert)

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/alerts")
    def api_alerts():
        limit = int(request.args.get("limit", 100))
        return jsonify(store.recent_alerts(limit=limit))

    @app.route("/api/inventory")
    def api_inventory():
        return jsonify(store.get_ap_inventory())

    @app.route("/api/stats")
    def api_stats():
        return jsonify(store.get_stats())

    @app.route("/api/eval")
    def api_eval():
        """Latest eval metrics badge (from data/reports/eval/metrics.json)."""
        path = PROJECT_ROOT / "data" / "reports" / "eval" / "metrics.json"
        sample = PROJECT_ROOT / "docs" / "sample_metrics.json"
        for candidate in (path, sample):
            if candidate.exists():
                data = json.loads(candidate.read_text(encoding="utf-8"))
                sig = data.get("signatures") or {}
                iso = data.get("isolation_forest") or {}
                am = data.get("anomaly_models") or {}
                if not iso and am:
                    iso = am.get("isolation_forest") or {}
                return jsonify(
                    {
                        "available": True,
                        "scenario_pass_rate": sig.get("scenario_pass_rate"),
                        "isolation_forest_roc_auc": iso.get("roc_auc"),
                        "ocsvm_roc_auc": (am.get("one_class_svm") or {}).get("roc_auc"),
                        "deauth_recommended_threshold": (
                            data.get("deauth_threshold_sweep") or {}
                        ).get("recommended_threshold"),
                        "source": str(candidate.relative_to(PROJECT_ROOT)),
                    }
                )
        return jsonify({"available": False})

    @app.route("/api/events/stream")
    def api_stream():
        q: queue.Queue = queue.Queue(maxsize=100)
        with clients_lock:
            clients.append(q)

        def generate():
            yield f"data: {json.dumps({'type': 'hello', 'ts': time.time()})}\n\n"
            try:
                while True:
                    try:
                        item = q.get(timeout=15)
                        yield f"data: {item}\n\n"
                    except queue.Empty:
                        yield f": keepalive {time.time()}\n\n"
            finally:
                with clients_lock:
                    try:
                        clients.remove(q)
                    except ValueError:
                        pass

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    return app


def run_dashboard(
    store: EventStore,
    host: str = "127.0.0.1",
    port: int = 8080,
    threaded: bool = True,
) -> None:
    app = create_app(store)
    app.run(host=host, port=port, threaded=threaded, use_reloader=False)
