from scapy.all import AsyncSniffer, IP, ARP, TCP, UDP, DNS, DNSQR
from queue import Queue
import time, ctypes
from datetime import datetime
from core.db import SessionLocal
from core.models import TrafficStat
from config import TRAFFIC_FLUSH_SEC

def _is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception: return True

def _get_iface():
    from core.db import SessionLocal
    from core.models import Setting
    with SessionLocal() as s:
        st = s.query(Setting).filter_by(key="sniffer_iface").one_or_none()
        return st.value if st else None

def _record_domain(ip, domain):
    from sqlalchemy import text
    from core.db import engine
    if not domain or not ip: return
    try:
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO domains (ip, domain, ts) VALUES (:ip, :domain, :ts)"),
                         {"ip": ip, "domain": domain, "ts": datetime.utcnow().isoformat()})
    except Exception as e:
        print("[sniffer] domain insert error:", e)

class Sniffer:
    def __init__(self):
        self.event_queue = Queue()
        self._counts = {}
        self._last = time.time()
        self._sniffer = None
        self._iface = None

    def _flush(self):
        if not self._counts: return
        now = datetime.utcnow()
        counts_copy = dict(self._counts)  # Make a copy before iterating
        with SessionLocal() as s:
            for ip, (pk, by) in counts_copy.items():
                row = s.query(TrafficStat).filter_by(ip=ip).one_or_none()
                if row is None:
                    row = TrafficStat(ip=ip, packets=pk, bytes=by, last_updated=now); s.add(row)
                else:
                    row.packets += pk; row.bytes += by; row.last_updated = now
            s.commit()
        self._counts.clear()

    def _inc(self, ip, size):
        if not ip: return
        pk, by = self._counts.get(ip, (0,0))
        self._counts[ip] = (pk+1, by+int(size))

    def _on_pkt(self, pkt):
        try: size = len(bytes(pkt))
        except Exception: size = 0

        # DNS (websites via DNS queries)
        if pkt.haslayer(UDP) and pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNS][DNSQR].qname
            if isinstance(qname, bytes): qname = qname.decode(errors="ignore")
            src = pkt[IP].src if pkt.haslayer(IP) else None
            if qname: _record_domain(src, qname.strip("."))
            # still count bytes
        # (HTTPS SNI is not reliably available without TLS parsing; omitted)

        # ARP
        if pkt.haslayer(ARP):
            self._inc(getattr(pkt,'psrc',None), size)
            self._inc(getattr(pkt,'pdst',None), size)
            return

        # IP/TCP/UDP
        if pkt.haslayer(IP):
            ip_src = pkt[IP].src; ip_dst = pkt[IP].dst
            self._inc(ip_src, size); self._inc(ip_dst, size)

    def _start(self, iface):
        self._sniffer = AsyncSniffer(prn=self._on_pkt, store=False, iface=iface, filter="arp or ip or udp port 53")
        self._sniffer.start()
        print(f"[sniffer] started on {iface} admin={_is_admin()}")

    def capture_loop(self):
        if not _is_admin():
            print("[sniffer] WARNING: Run PowerShell as Administrator on Windows for packet capture.")
        while True:
            try:
                desired = _get_iface()
                if desired and desired != self._iface:
                    if self._sniffer and self._sniffer.running:
                        try: self._sniffer.stop()
                        except Exception: pass
                    self._iface = desired; self._start(self._iface)
                if time.time() - self._last >= TRAFFIC_FLUSH_SEC:
                    self._flush(); self._last = time.time()
                time.sleep(0.4)
            except Exception as e:
                print("[sniffer] error:", e)
                time.sleep(1.0)
                try:
                    if self._sniffer and self._sniffer.running: self._sniffer.stop()
                except Exception: pass
                self._sniffer = None; self._iface = None
