from collections import defaultdict, deque
from time import time, sleep
from core.db import SessionLocal
from core.models import Alert
from config import SYN_BURST_THRESHOLD, ARP_SPOOF_WINDOW_SEC

class IDS:
    def __init__(self):
        self.syn_counts = defaultdict(int)
        self.syn_window = deque()
        self.arp_claims = defaultdict(dict)

    def _alert(self, severity, msg, meta=None):
        with SessionLocal() as s:
            s.add(Alert(severity=severity, message=msg, meta=meta or "")); s.commit()

    def _check_syn_burst(self):
        cutoff = time() - 10
        while self.syn_window and self.syn_window[0][0] < cutoff:
            _, saddr = self.syn_window.popleft()
            self.syn_counts[saddr] = max(0, self.syn_counts[saddr]-1)
        for saddr, cnt in list(self.syn_counts.items()):
            if cnt > SYN_BURST_THRESHOLD:
                self._alert("warning", f"High SYN rate from {saddr}", f"count={cnt}")

    def _check_arp_spoof(self):
        now = time()
        for ip, macmap in list(self.arp_claims.items()):
            recent_macs = [m for m, ts in macmap.items() if now - ts <= ARP_SPOOF_WINDOW_SEC]
            if len(recent_macs) > 1:
                self._alert("warning", f"Possible ARP spoofing on {ip}", f"macs={recent_macs}")

    def ids_loop(self, q):
        while True:
            try:
                evt = q.get()
                if evt["type"] == "tcp":
                    if evt.get("flags", 0) & 0x02 and not (evt.get("flags", 0) & 0x10):
                        ts = time()
                        self.syn_window.append((ts, evt["src"]))
                        self.syn_counts[evt["src"]] += 1
                        self._check_syn_burst()
                elif evt["type"] == "arp":
                    ip = evt.get("psrc"); mac = evt.get("hwsrc")
                    if ip and mac:
                        self.arp_claims[ip][mac] = time()
                        self._check_arp_spoof()
            except Exception as e:
                print("[ids] error:", e)
            sleep(0.01)
