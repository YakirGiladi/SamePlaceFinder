# app_same_place_v2.py
#
# Why v2? Your case "found nothing" is very common:
# - Gmail often hides the client IP (web/mobile Gmail → Google relay IPs)
# - Using only the top "Date" + 1-2 headers misses deeper "Received:" chain
# - 5min/200m might be too strict; and GeoIP is coarse
#
# Fixes in v2:
# 1) Fetch FULL RAW HEADERS and parse *all* Received lines (not just metadata)
# 2) Ignore private/reserved IPs and (optionally) known Google relay blocks
# 3) New matching modes:
#    --match either "geo" (distance) or "same_ip" (same public IP = same place)
# 4) Tunable window/distance: --window-seconds, --proximity-meters
# 5) Wider time union (uses both Date + internalDate as fallback)
#
# Usage:
#   pip3 install google-auth-oauthlib google-api-python-client requests python-dateutil haversine
#   python3 app_same_place_v2.py --creds client_secrets.json \
#     --account-a token_a.json --account-b token_b.json \
#     --start "2025-10-01T00:00:00" --end "2025-10-10T23:59:59" \
#     --match same_ip --window-seconds 1200
#
# Tips:
# - Try --match same_ip first (works even when GeoIP is poor)
# - If still empty, consider the Takeout-based approach (see second code block below)
#
import argparse
import base64
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone, timedelta
from dateutil import parser as dateparser

import requests
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from haversine import haversine, Unit

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

IPV4_RE = re.compile(r"(?<!\d)(\d{1,3}(?:\.\d{1,3}){3})(?!\d)")
PROXIMITY_METERS_DEFAULT = 200
WINDOW_SECONDS_DEFAULT = 5 * 60

# Known Google mail relays (partial/common; you can add more or disable this filter)
GOOGLE_RELAY_NETS = [
    "64.18.0.0/20", "64.233.160.0/19", "66.102.0.0/20", "66.249.80.0/20",
    "72.14.192.0/18", "74.125.0.0/16", "108.177.8.0/21", "173.194.0.0/16",
    "209.85.128.0/17", "216.239.32.0/19"
]
GOOGLE_RELAY_NETS = [ipaddress.ip_network(n) for n in GOOGLE_RELAY_NETS]

def ensure_credentials(client_secrets_path, token_path):
    flow = InstalledAppFlow.from_client_secrets_file(client_secrets_path, SCOPES)
    creds = flow.run_local_server(port=0)
    with open(token_path, "w") as f:
        json.dump({
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": creds.scopes
        }, f)
    return creds

def build_gmail(creds):
    return build("gmail", "v1", credentials=creds, cache_discovery=False)

def gmail_query_from_range(start_dt, end_dt):
    after = start_dt.strftime("%Y/%m/%d")
    before = (end_dt + timedelta(days=1)).strftime("%Y/%m/%d")
    return f"after:{after} before:{before}"

def list_ids(service, query):
    ids = []
    page = None
    while True:
        resp = service.users().messages().list(userId="me", q=query, pageToken=page, maxResults=500).execute()
        ids.extend([m["id"] for m in resp.get("messages", [])])
        page = resp.get("nextPageToken")
        if not page:
            break
    return ids

def fetch_raw(service, msg_id):
    msg = service.users().messages().get(userId="me", id=msg_id, format="raw").execute()
    internal_ts = int(msg.get("internalDate", 0)) / 1000.0 if msg.get("internalDate") else None
    raw_b64 = msg["raw"]
    raw_bytes = base64.urlsafe_b64decode(raw_b64.encode("utf-8"))
    raw = raw_bytes.decode(errors="replace")
    return raw, internal_ts

def parse_headers(raw):
    # Split headers from body
    parts = raw.split("\r\n\r\n", 1)
    head = parts[0]
    # Unfold headers (join lines that start with whitespace)
    unfolded = []
    cur = ""
    for line in head.splitlines():
        if line.startswith((" ", "\t")):
            cur += " " + line.strip()
        else:
            if cur:
                unfolded.append(cur)
            cur = line.strip()
    if cur:
        unfolded.append(cur)
    headers = {}
    for line in unfolded:
        if ":" in line:
            name, val = line.split(":", 1)
            headers.setdefault(name.strip(), []).append(val.strip())
    return headers

def is_public_ipv4(ip):
    try:
        ipobj = ipaddress.ip_address(ip)
        return ipobj.version == 4 and not (ipobj.is_private or ipobj.is_loopback or ipobj.is_multicast or ipobj.is_reserved)
    except ValueError:
        return False

def is_google_relay(ip):
    try:
        ipobj = ipaddress.ip_address(ip)
        return any(ipobj in net for net in GOOGLE_RELAY_NETS)
    except ValueError:
        return False

def extract_points(raw, prefer_internal_ts=None):
    headers = parse_headers(raw)
    # Determine a timestamp: Date header if present; else internalDate fallback
    ts = None
    for date_val in headers.get("Date", []):
        try:
            ts = dateparser.parse(date_val)
            break
        except Exception:
            pass
    if ts is None and prefer_internal_ts:
        ts = datetime.fromtimestamp(prefer_internal_ts, tz=timezone.utc)
    if ts and ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    # Collect IPs from all Received headers and X-Originating-IP
    ips = set()
    for k in ["X-Originating-IP", "X-Received", "Received"]:
        for v in headers.get(k, []):
            for m in IPV4_RE.finditer(v):
                ips.add(m.group(1))

    points = []
    for ip in ips:
        if not is_public_ipv4(ip):
            continue
        points.append({"ts": ts, "ip": ip})
    return points

def geoip(ip, cache, enable=True):
    if not enable:
        return None
    if ip in cache:
        return cache[ip]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,lat,lon,city,regionName,country,query", timeout=5)
        j = r.json()
        if j.get("status") == "success":
            cache[ip] = {"lat": j["lat"], "lon": j["lon"], "city": j.get("city"), "region": j.get("regionName"), "country": j.get("country")}
        else:
            cache[ip] = None
    except Exception:
        cache[ip] = None
    time.sleep(0.25)
    return cache[ip]

def build_timeline(service, label, query, filter_google_relays=True, do_geo=True):
    ids = list_ids(service, query)
    timeline = []
    cache = {}
    for mid in ids:
        raw, internal_ts = fetch_raw(service, mid)
        pts = extract_points(raw, prefer_internal_ts=internal_ts)
        for p in pts:
            if filter_google_relays and is_google_relay(p["ip"]):
                # likely a Google hop; skip
                continue
            g = geoip(p["ip"], cache, enable=do_geo)
            entry = {
                "ts": p["ts"],
                "ip": p["ip"],
                "lat": g["lat"] if g else None,
                "lon": g["lon"] if g else None,
                "city": g["city"] if g else None,
                "region": g["region"] if g else None,
                "country": g["country"] if g else None,
            }
            if entry["ts"]:
                timeline.append(entry)
    timeline = [e for e in timeline if e["ts"] is not None]
    timeline.sort(key=lambda x: x["ts"])
    print(f"{label}: {len(timeline)} points after filtering")
    return timeline

def find_overlaps(t1, t2, match="geo", proximity_m=PROXIMITY_METERS_DEFAULT, window_s=WINDOW_SECONDS_DEFAULT):
    matches = []
    for a in t1:
        for b in t2:
            if a["ts"] is None or b["ts"] is None:
                continue
            if abs((a["ts"] - b["ts"]).total_seconds()) > window_s:
                continue
            if match == "same_ip":
                if a["ip"] == b["ip"]:
                    matches.append({"ts": max(a["ts"], b["ts"]), "lat": a.get("lat") or b.get("lat"), "lon": a.get("lon") or b.get("lon"), "a": a, "b": b})
            else:  # geo
                if a["lat"] is None or a["lon"] is None or b["lat"] is None or b["lon"] is None:
                    continue
                d = haversine((a["lat"], a["lon"]), (b["lat"], b["lon"]), unit=Unit.METERS)
                if d <= proximity_m:
                    matches.append({"ts": max(a["ts"], b["ts"]), "lat": (a["lat"]+b["lat"])/2, "lon": (a["lon"]+b["lon"])/2, "a": a, "b": b})
    if not matches:
        return []
    matches.sort(key=lambda x: x["ts"])
    # Merge consecutive matches into windows if close in time
    windows = []
    cur = {"start": matches[0]["ts"], "end": matches[0]["ts"], "samples": [matches[0]]}
    for m in matches[1:]:
        if (m["ts"] - cur["end"]).total_seconds() <= window_s:
            cur["end"] = m["ts"]
            cur["samples"].append(m)
        else:
            windows.append(cur)
            cur = {"start": m["ts"], "end": m["ts"], "samples": [m]}
    windows.append(cur)
    # Keep windows ≥ 5 minutes OR at least 2 samples
    result = []
    for w in windows:
        dur = (w["end"] - w["start"]).total_seconds()
        if dur >= window_s or len(w["samples"]) >= 2:
            lat = None
            lon = None
            coords = [(s["lat"], s["lon"]) for s in w["samples"] if s["lat"] is not None and s["lon"] is not None]
            if coords:
                lat = sum(c[0] for c in coords)/len(coords)
                lon = sum(c[1] for c in coords)/len(coords)
            result.append({
                "start": w["start"].isoformat(),
                "end": w["end"].isoformat(),
                "duration_seconds": int(dur),
                "center_lat": lat,
                "center_lon": lon,
                "samples": len(w["samples"])
            })
    return result

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--creds", required=True)
    ap.add_argument("--account-a", required=True)
    ap.add_argument("--account-b", required=True)
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--match", choices=["geo", "same_ip"], default="geo")
    ap.add_argument("--proximity-meters", type=int, default=PROXIMITY_METERS_DEFAULT)
    ap.add_argument("--window-seconds", type=int, default=WINDOW_SECONDS_DEFAULT)
    ap.add_argument("--no-relay-filter", action="store_true", help="Do NOT filter known Google relay IP ranges")
    args = ap.parse_args()

    start_dt = dateparser.parse(args.start).astimezone(timezone.utc)
    end_dt = dateparser.parse(args.end).astimezone(timezone.utc)
    q = gmail_query_from_range(start_dt, end_dt)

    print("Authorize A …")
    creds_a = ensure_credentials(args.creds, args.account_a)
    srv_a = build_gmail(creds_a)
    print("Authorize B …")
    creds_b = ensure_credentials(args.creds, args.account_b)
    srv_b = build_gmail(creds_b)

    t_a = build_timeline(srv_a, "A", q, filter_google_relays=not args.no_relay_filter, do_geo=(args.match=="geo"))
    t_b = build_timeline(srv_b, "B", q, filter_google_relays=not args.no_relay_filter, do_geo=(args.match=="geo"))

    windows = find_overlaps(t_a, t_b, match=args.match, proximity_m=args.proximity_meters, window_s=args.window_seconds)
    print(json.dumps(windows, indent=2))
    with open("same_place_windows.json", "w") as f:
        json.dump(windows, f, indent=2)
    print("Saved: same_place_windows.json")

if __name__ == "__main__":
    main()
