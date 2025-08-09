import threading
from flask import Flask, render_template, jsonify, request
from core.db import init_db, SessionLocal
from core.models import Device, Port, TrafficStat, Alert
from scanners.discovery import Discovery
from monitor.sniffer import Sniffer
from monitor.ids import IDS
from reports.report import generate_html_report
from core.utils import list_interfaces, get_setting, set_setting

def create_app():
    app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
    init_db()

    if not get_setting("sniffer_iface"):
        ifs = list_interfaces()
        if ifs: set_setting("sniffer_iface", ifs[0]["name"])

    discovery = Discovery(); sniffer = Sniffer(); ids = IDS()
    started=False; import threading
    lock=threading.Lock()
    def start_once():
        nonlocal started
        with lock:
            if not started:
                threading.Thread(target=discovery.scan_loop, daemon=True).start()
                threading.Thread(target=sniffer.capture_loop, daemon=True).start()
                threading.Thread(target=ids.ids_loop, args=(sniffer.event_queue,), daemon=True).start()
                started=True
    @app.before_request
    def ensure(): start_once()

    @app.route("/")
    def index(): return render_template("index.html")
    @app.route("/devices")
    def devices_page(): return render_template("devices.html")
    @app.route("/traffic")
    def traffic_page(): return render_template("traffic.html")

    @app.route("/alerts")
    def alerts_page(): return render_template("alerts.html")

    @app.route("/api/status")
    def api_status():
        return jsonify({"iface": get_setting("sniffer_iface"), "adapters": list_interfaces()})

    @app.route("/api/set_iface", methods=["POST"])
    def api_set_iface():
        iface = request.json.get("iface")
        if not iface: return jsonify({"ok": False, "msg": "iface required"}), 400
        set_setting("sniffer_iface", iface); return jsonify({"ok": True})

    @app.route("/api/devices")
    def api_devices():
        with SessionLocal() as s:
            q = s.query(Device).order_by(Device.last_seen.desc()).all()
            return jsonify([d.to_dict() for d in q])

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        host = request.json.get("host")
        full = bool(request.json.get("full", False))
        ok, msg = Discovery.scan_now(host=host, full=full)
        return jsonify({"ok": ok, "msg": msg})

    @app.route("/api/traffic")
    def api_traffic():
        with SessionLocal() as s:
            q = s.query(TrafficStat).order_by(TrafficStat.bytes.desc()).limit(200).all()
            return jsonify([t.to_dict() for t in q])

    @app.route("/api/alerts")
    def api_alerts():
        with SessionLocal() as s:
            q = s.query(Alert).order_by(Alert.ts.desc()).limit(200).all()
            return jsonify([a.to_dict() for a in q])

    @app.route("/api/domains/<ip>")
    def api_domains(ip):
        from sqlalchemy import text
        from core.db import engine
        rows=[]
        with engine.connect() as conn:
            res = conn.execute(text("SELECT domain, ts FROM domains WHERE ip=:ip ORDER BY id DESC LIMIT 100"), {"ip": ip})
            rows = [{"domain": r[0], "ts": r[1]} for r in res.fetchall()]
        return jsonify(rows)

    @app.route("/api/report")
    def api_report():
        path = generate_html_report()
        return jsonify({"ok": True, "path": path})

    return app
