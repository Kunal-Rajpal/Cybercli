# cybercli/core/net_utils.py
import socket, subprocess
from typing import List, Dict, Any

def quick_connect_scan(host: str, ports: List[int], timeout:float=0.5) -> List[int]:
    open_ports = []
    for p in ports:
        try:
            s = socket.socket(); s.settimeout(timeout)
            if s.connect_ex((host, p)) == 0:
                open_ports.append(p)
            s.close()
        except Exception:
            pass
    return open_ports

def run_nmap(ip: str, timeout: int = 300) -> Dict[str, Any]:
    out = {"ip": ip, "open_ports": []}
    try:
        proc = subprocess.run(["nmap","-sV","-Pn","--host-timeout","30s",ip],
                              capture_output=True,text=True,timeout=timeout)
        out["nmap_raw"] = proc.stdout
        for line in proc.stdout.splitlines():
            if "open" in line and ("/tcp" in line or "/udp" in line):
                try:
                    port = int(line.split("/")[0]) if "/" in line else None
                except Exception:
                    port = None
                service = " ".join(line.split()[2:]) if len(line.split())>2 else line.strip()
                out["open_ports"].append({"port": port, "service": service, "raw": line})
    except Exception as e:
        out["error"] = str(e)
    return out

