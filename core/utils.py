import socket, psutil, subprocess, ipaddress
from core.db import SessionLocal
from core.models import Setting

def get_setting(key, default=None):
    with SessionLocal() as s:
        row = s.query(Setting).filter_by(key=key).one_or_none()
        return row.value if row else default

def set_setting(key, value):
    with SessionLocal() as s:
        row = s.query(Setting).filter_by(key=key).one_or_none()
        if row is None:
            row = Setting(key=key, value=str(value)); s.add(row)
        else:
            row.value = str(value)
        s.commit()

def list_interfaces():
    out = []
    for name, addrs in psutil.net_if_addrs().items():
        ipv4 = [a.address for a in addrs if a.family == socket.AF_INET and not a.address.startswith("127.")]
        up = psutil.net_if_stats().get(name).isup if psutil.net_if_stats().get(name) else False
        if ipv4 and up:
            out.append({"name": name, "ipv4": ipv4})
    return out

def active_subnet_for_iface(iface_name):
    for name, addrs in psutil.net_if_addrs().items():
        if name != iface_name: continue
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith("127."):
                netmask = a.netmask or "255.255.255.0"
                return str(ipaddress.IPv4Network(f"{a.address}/{netmask}", strict=False))
    return None
