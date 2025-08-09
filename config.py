import os
DB_URL = os.environ.get("WM_DB_URL", "sqlite:///./data/wifimon.db")
DISCOVERY_INTERVAL_SEC = int(os.environ.get("WM_DISCOVERY_SEC", "90"))
TRAFFIC_FLUSH_SEC = int(os.environ.get("WM_TRAFFIC_FLUSH_SEC", "3"))
SYN_BURST_THRESHOLD = int(os.environ.get("WM_SYN_BURST", "200"))
ARP_SPOOF_WINDOW_SEC = int(os.environ.get("WM_ARP_WIN", "60"))
