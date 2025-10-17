# app_same_place.py
#
# Purpose:
#   - Input: two Gmail accounts (via OAuth) + time range
#   - Output: time windows where both accounts appear to be
#     in the same place for ~5 minutes (approximate, based on
#     message headers IP -> geoip -> timestamp)
#
# Notes:
#   - This is a best-effort approach using email headers.
#     Accuracy depends on presence of IPs in headers and
#     geoip precision (carrier NAT, VPNs, Gmail internal mail relays etc).
#   - You must consent both Gmail accounts to allow the app read-only Gmail scopes.
#
# Dependencies:
#   pip install google-auth-oauthlib google-api-python-client requests python-dateutil haversine
#
# How to run (example):
#   python app_same_place.py --creds client_secrets.json --account-a token_a.json \
#       --account-b token_b.json --start "2025-10-01T00:00:00" --end "2025-10-10T23:59:59"
#

import argparse
import json
import os
import re
import time
from datetime import datetime, timezone, timedelta
from dateutil import parser as dateparser

import requests
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from haversine import haversine, Unit

# -------------------------
# Configuration / defaults
# -------------------------
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
IP_HEADER_KEYS = ["X-Originating-IP", "X-Received", "Received"]
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
GEOIP_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,query,timezone,isp,org"  # free and simple
PROXIMITY_METERS = 200       # consider "same place" within 200 meters
MIN_DURATION_SECONDS = 5 * 60  # ~5 minutes

# -------------------------
# Utilities
# -------------------------
def ensure_credentials(client_secrets_path, token_path):
    """
    Uses OAuth installed flow to create or refresh token for a Gmail account.
    Returns credentials object.
    """
    creds = None
    if os.path.exists(token_path):
        with open(token_path, "r") as f:
            token = json.load(f)
        # token contains refresh token and expiry; we'll use google-auth helper to refresh
        # Simpler: run full flow every time if token not present or expired.
        # We'll implement simple InstalledAppFlow that stores token to token_path.
    flow = InstalledAppFlow.from_client_secrets_file(client_secrets_path, SCOPES)
    creds = flow.run_local_server(port=0)
    # save for reuse
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

def build_gmail_service(creds):
    return build("gmail", "v1", credentials=creds, cache_discovery=False)

def list_message_ids(service, user_id="me", query=None):
    """Return list of message ids matching query (can be date range query)."""
    ids = []
    page_token = None
    while True:
        resp = service.users().messages().list(userId=user_id, q=query, pageToken=page_token, maxResults=500).execute()
        if "messages" in resp:
            ids.extend([m["id"] for m in resp["messages"]])
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return ids

def get_message_metadata(service, msg_id, user_id="me"):
    """Fetch only headers and internalDate to reduce bandwidth."""
    msg = service.users().messages().get(userId=user_id, id=msg_id, format="metadata", metadataHeaders=['Date']).execute()
    # If we want all headers: metadataHeaders=['Date','Received','X-Originating-IP', ...]
    return msg

def parse_headers_for_ips(msg):
    """
    Parse message metadata headers to extract (timestamp, ip) points.
    We will use the Date header timestamp as the timestamp for the associated IPs found in the headers.
    Returns list of dicts: {"ts": datetime, "ip": "x.x.x.x", "raw_header": "..." }
    """
    headers = {h['name']: h['value'] for h in msg.get("payload", {}).get("headers", [])}
    date_str = headers.get("Date")
    pts = []
    try:
        ts = dateparser.parse(date_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except Exception:
        ts = datetime.fromtimestamp(int(msg.get("internalDate", 0)) / 1000, tz=timezone.utc)

    # search Received header bodies (may be multiple) & X-Originating-IP
    for key in IP_HEADER_KEYS:
        val = headers.get(key)
        if not val:
            # Received often shows up multiple times; Gmail metadata may return only first.
            # For robustness, examine 'raw' message (not done here for perf).
            continue
        for m in IP_RE.finditer(val):
            ip = m.group(1)
            pts.append({"ts": ts, "ip": ip, "source_header": key, "raw": val})
    return pts

def geoip_lookup(ip):
    """Return dict with lat, lon, city, region, country, timezone. Uses ip-api.com (free)."""
    try:
        r = requests.get(GEOIP_URL.format(ip=ip), timeout=5)
        j = r.json()
        if j.get("status") != "success":
            return None
        return {"ip": j.get("query"), "lat": j.get("lat"), "lon": j.get("lon"),
                "city": j.get("city"), "region": j.get("regionName"), "country": j.get("country"),
                "timezone": j.get("timezone"), "isp": j.get("isp"), "org": j.get("org")}
    except Exception:
        return None

# -------------------------
# Core processing
# -------------------------
def build_timeline_for_account(service, user_label, query, geoip_cache):
    """
    Builds a timeline: list of dicts {ts: datetime, lat: float, lon: float, ip: str, note: str}
    - query: Gmail query string (e.g., after:YYYY/MM/DD before:YYYY/MM/DD)
    - geoip_cache: dict ip -> geo dict (to avoid repeated queries)
    """
    timeline = []
    ids = list_message_ids(service, user_id="me", query=query)
    print(f"{user_label}: found {len(ids)} messages in range (may include messages without useful headers).")
    for mid in ids:
        msg = get_message_metadata(service, mid, user_id="me")
        points = parse_headers_for_ips(msg)
        for p in points:
            ip = p["ip"]
            if ip not in geoip_cache:
                geoip_cache[ip] = geoip_lookup(ip)
                time.sleep(0.35)  # be nice to the free geoip API
            geo = geoip_cache[ip]
            if not geo:
                continue
            timeline.append({
                "ts": p["ts"].astimezone(timezone.utc),
                "lat": geo["lat"],
                "lon": geo["lon"],
                "ip": ip,
                "city": geo.get("city"),
                "region": geo.get("region"),
                "country": geo.get("country"),
                "source_header": p.get("source_header"),
                "raw_header": p.get("raw"),
            })
    # sort by timestamp
    timeline.sort(key=lambda x: x["ts"])
    return timeline

def find_overlap_windows(t1, t2, proximity_meters=PROXIMITY_METERS, min_duration_s=MIN_DURATION_SECONDS):
    """
    t1, t2: lists of {ts, lat, lon, ...}
    Approach (approximate):
      - For each point in t1, look for points in t2 within +/- min_duration_s time window.
      - If distance <= proximity_meters and time difference <= min_duration_s window, record as potential meeting moment.
      - Merge consecutive matches (by time) to produce windows and check if window length >= min_duration_s.
    Returns list of windows: {"start": dt, "end": dt, "center": (lat,lon), "samples": [...]} 
    """
    matches = []
    i = 0
    for a in t1:
        for b in t2:
            dt_diff = abs((a["ts"] - b["ts"]).total_seconds())
            if dt_diff <= min_duration_s:  # messages close in time
                dist_m = haversine((a["lat"], a["lon"]), (b["lat"], b["lon"]), unit=Unit.METERS)
                if dist_m <= proximity_meters:
                    ts = min(a["ts"], b["ts"])
                    matches.append({"ts": ts, "lat": (a["lat"] + b["lat"]) / 2.0, "lon": (a["lon"] + b["lon"]) / 2.0, "a": a, "b": b})
    if not matches:
        return []
    # merge matches into windows (consecutive matches within min_duration_s)
    matches.sort(key=lambda x: x["ts"])
    windows = []
    cur = {"start": matches[0]["ts"], "end": matches[0]["ts"], "samples": [matches[0]]}
    for m in matches[1:]:
        if (m["ts"] - cur["end"]).total_seconds() <= min_duration_s:
            cur["end"] = m["ts"]
            cur["samples"].append(m)
        else:
            windows.append(cur)
            cur = {"start": m["ts"], "end": m["ts"], "samples": [m]}
    windows.append(cur)
    # prune windows shorter than min_duration_s
    result = []
    for w in windows:
        dur = (w["end"] - w["start"]).total_seconds()
        if dur >= min_duration_s or len(w["samples"]) >= 2:
            # compute center lat/lon average
            lat = sum(s["lat"] for s in w["samples"]) / len(w["samples"])
            lon = sum(s["lon"] for s in w["samples"]) / len(w["samples"])
            result.append({"start": w["start"], "end": w["end"], "center": (lat, lon), "samples": w["samples"], "duration_s": dur})
    return result

# -------------------------
# CLI / Main
# -------------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--creds", required=True, help="OAuth client_secrets.json path (Google Console)")
    p.add_argument("--account-a", required=True, help="Path to token file for account A (will be created if missing)")
    p.add_argument("--account-b", required=True, help="Path to token file for account B (will be created if missing)")
    p.add_argument("--start", required=True, help="ISO start datetime (e.g. 2025-10-01T00:00:00)")
    p.add_argument("--end", required=True, help="ISO end datetime (e.g. 2025-10-10T23:59:59)")
    p.add_argument("--q-a", default=None, help="Optional extra Gmail query for account A (labels, from:, subject:)")
    p.add_argument("--q-b", default=None, help="Optional extra Gmail query for account B")
    args = p.parse_args()

    start_dt = dateparser.parse(args.start).astimezone(timezone.utc)
    end_dt = dateparser.parse(args.end).astimezone(timezone.utc)
    # Gmail q filter uses 'after:YYYY/MM/DD before:YYYY/MM/DD' (dates are inclusive/exclusive nuances)
    # Convert to date-only for query - Gmail queries do not accept ISO times. We'll use dates.
    gmail_after = start_dt.strftime("%Y/%m/%d")
    # before should be day after end date
    gmail_before = (end_dt + timedelta(days=1)).strftime("%Y/%m/%d")
    query_a = f"after:{gmail_after} before:{gmail_before}"
    query_b = f"after:{gmail_after} before:{gmail_before}"
    if args.q_a:
        query_a += " " + args.q_a
    if args.q_b:
        query_b += " " + args.q_b

    print("STEP: ensure credentials for Account A")
    creds_a = ensure_credentials(args.creds, args.account_a)
    service_a = build_gmail_service(creds_a)
    print("STEP: ensure credentials for Account B")
    creds_b = ensure_credentials(args.creds, args.account_b)
    service_b = build_gmail_service(creds_b)

    geoip_cache = {}
    print("STEP: build timeline for Account A")
    t_a = build_timeline_for_account(service_a, "Account A", query_a, geoip_cache)
    print("STEP: build timeline for Account B")
    t_b = build_timeline_for_account(service_b, "Account B", query_b, geoip_cache)

    print(f"Account A points: {len(t_a)}, Account B points: {len(t_b)}")
    windows = find_overlap_windows(t_a, t_b)
    out = []
    for w in windows:
        out.append({
            "start": w["start"].isoformat(),
            "end": w["end"].isoformat(),
            "duration_seconds": int(w["duration_s"]),
            "center_lat": w["center"][0],
            "center_lon": w["center"][1],
            "samples_count": len(w["samples"])
        })
    print("=== RESULTS ===")
    print(json.dumps(out, indent=2))
    # Optionally save to file
    with open("same_place_windows.json", "w") as f:
        json.dump(out, f, indent=2)
    print("Saved same_place_windows.json")

if __name__ == "__main__":
    main()
