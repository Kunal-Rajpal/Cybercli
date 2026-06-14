# cybercli/core/correlation_core.py
"""
Correlation engine to group and find relationships in security events.
- Groups events by indicator overlap (IP, domain, hash, user, asset).
- Produces clusters, simple timeline correlation, and quick insights.
- SAFE: pure analysis of provided data; does not fetch external data.

Usage:
    from cybercli.core.correlation_core import CorrelationCore
    cc = CorrelationCore()
    cc.correlate(events_list)
"""
from __future__ import annotations
from typing import List, Dict, Any, Tuple
from collections import defaultdict
import datetime
import re

INDICATOR_KEYS = ("ip", "domain", "hash", "user", "host", "hostname", "url", "email")

def _extract_indicators(event: Dict[str, Any]) -> List[str]:
    out = []
    text = " ".join(str(v) for v in event.values() if isinstance(v, (str, int, float)))
    # simple regexes
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    domains = re.findall(r"\b[a-z0-9.-]+\.[a-z]{2,}\b", text.lower())
    hashes = re.findall(r"\b[a-f0-9]{32,64}\b", text.lower())
    emails = re.findall(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", text.lower())
    out.extend(ips)
    out.extend(domains)
    out.extend(hashes)
    out.extend(emails)
    return list(set(out))

class CorrelationCore:
    """
    Basic correlation engine.
    Methods:
        correlate(events: List[Dict]) -> Dict with clusters & insights
    """

    def __init__(self):
        # simple time window default in seconds
        self.time_window = 3600

    def correlate(self, events: List[Dict]) -> Dict:
        """
        events is a list of dicts. Each event ideally has 'timestamp' (ISO) and 'source' and 'message' fields.
        Returns:
            {
                "clusters": [ { "indicators": [...], "events": [...], "first_seen": ..., "last_seen": ... }, ... ],
                "insights": "...",
            }
        """
        if not events:
            return {"clusters": [], "insights": "no events"}

        # normalize and extract indicators
        normalized = []
        for e in events:
            ev = dict(e)  # shallow copy
            ts = ev.get("timestamp")
            if ts:
                try:
                    ev["_ts"] = datetime.datetime.fromisoformat(ts)
                except Exception:
                    ev["_ts"] = None
            else:
                ev["_ts"] = None
            ev["_indicators"] = _extract_indicators(ev)
            normalized.append(ev)

        # cluster by shared indicators
        idx_by_indicator = defaultdict(list)
        for i, ev in enumerate(normalized):
            for ind in ev["_indicators"]:
                idx_by_indicator[ind].append(i)

        # build clusters as sets of event indices
        clusters_idx = []
        visited = set()
        for ind, idxs in idx_by_indicator.items():
            # merge overlapping sets
            current = set(idxs)
            merged = True
            while merged:
                merged = False
                for other in clusters_idx:
                    if current & other:
                        current = current | other
                        clusters_idx.remove(other)
                        merged = True
                        break
            clusters_idx.append(current)

        # convert clusters
        clusters = []
        for c in clusters_idx:
            evs = [normalized[i] for i in sorted(c)]
            inds = set()
            first_ts = None
            last_ts = None
            for ev in evs:
                inds.update(ev["_indicators"])
                if ev["_ts"]:
                    if not first_ts or ev["_ts"] < first_ts:
                        first_ts = ev["_ts"]
                    if not last_ts or ev["_ts"] > last_ts:
                        last_ts = ev["_ts"]
            clusters.append({
                "indicators": sorted(list(inds)),
                "events": evs,
                "first_seen": first_ts.isoformat() if first_ts else None,
                "last_seen": last_ts.isoformat() if last_ts else None,
                "count": len(evs)
            })

        insights = f"{len(clusters)} correlated clusters from {len(events)} events"
        return {"clusters": clusters, "insights": insights}

