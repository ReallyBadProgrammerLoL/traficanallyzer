"""Веб-плоскость управления — живые алерты (SSE) + REST API к контроллеру.
Посредством Flask: потоки /stream (алерты) и /traffic (весь трафик), эндпоинты
/api/* (статус, scope, правила, DPI, scan)."""

from __future__ import annotations
import json
import os
import threading

from flask import Flask, Response, request, jsonify, render_template, stream_with_context

from controller import Controller


def _interfaces() -> list[str]:
    try:
        return sorted(os.listdir("/sys/class/net"))
    except OSError:
        return ["lo"]


def _home_net_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [v.strip() for v in value if v.strip()]
    return [v.strip() for v in str(value).split(",") if v.strip()]


def create_app(controller: Controller) -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template("index.html")

    def _sse(hub):
        @stream_with_context
        def gen():
            q = hub.subscribe()
            try:
                yield "retry: 2000\n\n"
                while True:
                    yield f"data: {json.dumps(q.get())}\n\n"
            finally:
                hub.unsubscribe(q)
        return Response(gen(), mimetype="text/event-stream")

    @app.route("/stream")
    def stream():
        return _sse(controller.hub)        # security alerts

    @app.route("/traffic")
    def traffic():
        return _sse(controller.traffic)    # every packet

    # --- status / scope ---------------------------------------------------
    @app.get("/api/status")
    def status():
        s = controller.status()
        s["interfaces"] = _interfaces()
        return jsonify(s)

    @app.post("/api/scope")
    def set_scope():
        body = request.get_json(silent=True) or {}
        controller.set_scope(
            iface=body.get("iface"),
            home_net=_home_net_list(body.get("home_net")),
            default_policy=body.get("default_policy"),
        )
        return jsonify(controller.status())

    @app.post("/api/monitor")
    def set_monitor():
        body = request.get_json(silent=True) or {}
        if body.get("enabled"):
            controller.enable_monitor()
        else:
            controller.disable_monitor()
        return jsonify(controller.status())

    @app.post("/api/protection")
    def set_protection():
        body = request.get_json(silent=True) or {}
        if body.get("enabled"):
            try:
                controller.enable_protection()
            except Exception as exc:
                return jsonify({"error": str(exc)}), 500
        else:
            controller.disable_protection()
        return jsonify(controller.status())

    # --- rules ------------------------------------------------------------
    @app.get("/api/rules")
    def get_rules():
        return jsonify({"text": controller.store.text()})

    @app.post("/api/rules")
    def save_rules():
        body = request.get_json(silent=True) or {}
        text = body.get("text", "")
        errors = controller.store.save_text(text)
        if errors:
            return jsonify({"errors": errors}), 400
        controller.reload_rules()
        return jsonify({"ok": True, "rules": len(controller.store.rules)})

    @app.post("/api/reload")
    def reload_rules():
        controller.reload_rules()
        return jsonify({"ok": True, "rules": len(controller.store.rules)})

    # --- DPI config -------------------------------------------------------
    @app.get("/api/dpi")
    def get_dpi():
        return jsonify(controller.dpi_config())

    @app.post("/api/dpi")
    def save_dpi():
        body = request.get_json(silent=True) or {}
        errors = controller.save_dpi(body)
        if errors:
            return jsonify({"errors": errors}), 400
        return jsonify({"ok": True})

    # --- scan / correlation thresholds ------------------------------------
    @app.get("/api/scan")
    def get_scan():
        return jsonify(controller.scan_config())

    @app.post("/api/scan")
    def save_scan():
        body = request.get_json(silent=True) or {}
        errors = controller.save_scan(body)
        if errors:
            return jsonify({"errors": errors}), 400
        return jsonify({"ok": True})

    return app


def run_in_thread(controller: Controller, host: str = "127.0.0.1",
                  port: int = 8080) -> threading.Thread:
    app = create_app(controller)

    def _serve() -> None:
        app.run(host=host, port=port, threaded=True, use_reloader=False)

    t = threading.Thread(target=_serve, daemon=True, name="web")
    t.start()
    return t
