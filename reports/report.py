from datetime import datetime
from core.db import SessionLocal
from core.models import Device, Port, TrafficStat, Alert

def generate_html_report(path: str = "data/report.html"):
    with SessionLocal() as s:
        devices = s.query(Device).all()
        traffic = s.query(TrafficStat).order_by(TrafficStat.bytes.desc()).limit(50).all()
        alerts = s.query(Alert).order_by(Alert.ts.desc()).limit(100).all()
    html = ["<html><head><meta charset='utf-8'><title>Network Report</title>",
            "<style>body{font-family:Arial} table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:6px} th{background:#eee}</style>",
            "</head><body>"]
    html.append(f"<h1>Network Report</h1><p>Generated: {datetime.utcnow().isoformat()}Z</p>")
    html.append("<h2>Devices</h2><table><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th><th>OS</th><th>Open Ports</th></tr>")
    for d in devices:
        ports = ", ".join([f"{p.port}/{p.proto} {p.service or ''} {p.version or ''}" for p in d.ports]) or "-"
        html.append(f"<tr><td>{d.ip}</td><td>{d.mac or '-'}</td><td>{d.hostname or '-'}</td><td>{d.vendor or '-'}</td><td>{d.os_name or '-'}</td><td>{ports}</td></tr>")
    html.append("</table>")
    html.append("<h2>Top Traffic</h2><table><tr><th>IP</th><th>Packets</th><th>Bytes</th><th>Last Updated</th></tr>")
    for t in traffic:
        html.append(f"<tr><td>{t.ip}</td><td>{t.packets}</td><td>{t.bytes}</td><td>{t.last_updated}</td></tr>")
    html.append("</table>")
    html.append("<h2>Recent Alerts</h2><table><tr><th>Time</th><th>Severity</th><th>Message</th><th>Meta</th></tr>")
    for a in alerts:
        html.append(f"<tr><td>{a.ts}</td><td>{a.severity}</td><td>{a.message}</td><td>{a.meta or ''}</td></tr>")
    html.append("</table></body></html>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(html))
    return path
