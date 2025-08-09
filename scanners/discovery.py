import os, time, shutil
from datetime import datetime
from core.db import SessionLocal
from core.models import Device, Port
from core.utils import active_subnet_for_iface, get_setting
from config import DISCOVERY_INTERVAL_SEC

try:
    import nmap
except Exception:
    nmap = None

from scapy.all import ARP, Ether, srp

def _update_device(session, ip, hostname=None, mac=None, vendor=None, os_name=None):
    d = session.query(Device).filter_by(ip=ip).one_or_none()
    now = datetime.utcnow()
    if d is None:
        d = Device(ip=ip, hostname=hostname, mac=mac, vendor=vendor, os_name=os_name, first_seen=now, last_seen=now)
        session.add(d)
    else:
        d.hostname = hostname or d.hostname
        d.mac = mac or d.mac
        d.vendor = vendor or d.vendor
        d.os_name = os_name or d.os_name
        d.last_seen = now
    session.commit()
    return d

def _arp_sweep(cidr):
    devices = []
    if not cidr: return devices
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=cidr)
        ans, _ = srp(pkt, timeout=2, verbose=0)
        for _, r in ans:
            devices.append({"ip": r.psrc, "mac": r.hwsrc})
    except Exception as e:
        print("[discovery] arp error:", e)
    return devices

class Discovery:
    def __init__(self):
        self.nmap_bin = shutil.which("nmap")
        if not self.nmap_bin:
            for p in (r"C:\Tools\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe", r"C:\Program Files (x86)\Nmap\nmap.exe"):
                if os.path.exists(p): self.nmap_bin = p; break
        self.nm = None
        if nmap and self.nmap_bin:
            try: self.nm = nmap.PortScanner(nmap_search_path=(self.nmap_bin,))
            except Exception: self.nm = None

    def scan_loop(self):
        while True:
            try:
                iface = get_setting("sniffer_iface")
                cidr = active_subnet_for_iface(iface) if iface else None
                if self.nm is not None and cidr:
                    self.nm.scan(hosts=cidr, arguments="-sn")
                    with SessionLocal() as s:
                        for host in self.nm.all_hosts():
                            if self.nm[host].state() != "up": continue
                            hname = self.nm[host].hostname()
                            mac = self.nm[host]['addresses'].get('mac') if 'addresses' in self.nm[host] else None
                            _update_device(s, host, hname, mac)
                else:
                    with SessionLocal() as s:
                        for d in _arp_sweep(cidr):
                            _update_device(s, d["ip"], mac=d.get("mac"))
            except Exception as e:
                print("[discovery] loop error: Network scan error - will retry")
                if hasattr(e, '__str__') and not str(e).startswith('<?xml'):
                    print("[discovery] error details:", e)
            time.sleep(DISCOVERY_INTERVAL_SEC)

    @staticmethod
    def scan_now(host: str = None, full: bool = False):
        try:
            iface = get_setting("sniffer_iface")
            cidr = active_subnet_for_iface(iface) if iface else None
            targets = host or cidr
            if not targets:
                return False, "No target/subnet (select interface in header)"
            if nmap and (shutil.which("nmap") or os.path.exists(r"C:\Tools\Nmap\nmap.exe") or os.path.exists(r"C:\Program Files\Nmap\nmap.exe") or os.path.exists(r"C:\Program Files (x86)\Nmap\nmap.exe")):
                candidates = [p for p in (shutil.which("nmap"), r"C:\Tools\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe", r"C:\Program Files (x86)\Nmap\nmap.exe") if p and os.path.exists(p)]
                nm = nmap.PortScanner(nmap_search_path=(candidates[0],)) if candidates else nmap.PortScanner()
                args = "-Pn -T4 " + ("-sS -sV -O" if full else "-sS")
                nm.scan(hosts=targets, arguments=args)
                with SessionLocal() as s:
                    for h in nm.all_hosts():
                        if nm[h].state() != "up": continue
                        hname = nm[h].hostname()
                        mac = nm[h]['addresses'].get('mac') if 'addresses' in nm[h] else None
                        dev = _update_device(s, h, hname, mac)
                        s.query(Port).filter_by(device_id=dev.id).delete()
                        if 'tcp' in nm[h]:
                            for p, meta in nm[h]['tcp'].items():
                                if meta.get('state') == 'open':
                                    s.add(Port(device_id=dev.id, port=p, proto='tcp', state='open', service=meta.get('name'), version=meta.get('version')))
                        s.commit()
                return True, "Scan complete (Nmap)"
            else:
                with SessionLocal() as s:
                    for d in _arp_sweep(targets):
                        _update_device(s, d["ip"], mac=d.get("mac"))
                return True, "ARP sweep complete (no Nmap)"
        except Exception as e:
            return False, str(e)
