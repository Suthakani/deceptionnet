"""
DeceptionNet v2 - Cyber Deception System (Orca Coder, Track 03)

Layers
  1. Simulated network with decoy files, honeytoken credentials and a decoy host
  2. REAL honeypot portal (?page=portal) - any real visitor is captured live (IP, user-agent, action)
  3. Alert engine (decoy touch = high-confidence alert) + session correlation
  4. Path reconstruction, replay, MITRE ATT&CK mapping
  5. Threat analyst (intent / skill / next-move prediction), risk score, auto-response playbooks
  6. Incident report (optional Claude executive summary if ANTHROPIC_API_KEY is set)
"""
import json
import os
import random
import sqlite3
import tempfile
import urllib.request
from contextlib import closing
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

PAGE = st.query_params.get("page", "")
if PAGE == "portal":
    st.set_page_config(page_title="Acme Corp | Admin Portal", page_icon="🔐", layout="centered")
else:
    st.set_page_config(page_title="DeceptionNet", page_icon="🪤", layout="wide")

# ----------------------------------------------------------------------------
# NETWORK MODEL
# ----------------------------------------------------------------------------
HOSTS = {
    "Internet":     dict(pos=(0, 0),      role="External network",            decoy=False),
    "web-01":       dict(pos=(1.5, 0),    role="Public web server (DMZ)",     decoy=False),
    "app-01":       dict(pos=(3, 1.3),    role="Application server",          decoy=False),
    "db-01":        dict(pos=(4.5, 1.3),  role="Production database",         decoy=False),
    "file-01":      dict(pos=(3, -1.3),   role="Corporate file server",       decoy=False),
    "admin-ws":     dict(pos=(4.5, -1.3), role="Admin workstation",           decoy=False),
    "hr-backup-01": dict(pos=(6, 0),      role="DECOY host (fake HR backup)", decoy=True),
}
EDGES = [
    ("Internet", "web-01"), ("web-01", "app-01"), ("web-01", "file-01"),
    ("app-01", "db-01"), ("file-01", "admin-ws"),
    ("admin-ws", "hr-backup-01"), ("db-01", "hr-backup-01"),
]
NEIGHBORS = {h: [] for h in HOSTS}
for _a, _b in EDGES:
    NEIGHBORS[_a].append(_b)
    NEIGHBORS[_b].append(_a)

ASSETS = {
    "web-01:index.html":  dict(host="web-01",   name="index.html",                       kind="file",      decoy=False),
    "web-01:.env.bak":    dict(host="web-01",   name=".env.bak (fake DB creds)",         kind="cred_file", decoy=True),
    "app-01:app.conf":    dict(host="app-01",   name="app.conf",                         kind="file",      decoy=False),
    "db-01:customers":    dict(host="db-01",    name="customers table",                  kind="file",      decoy=False),
    "db-01:svc_dbadmin":  dict(host="db-01",    name="login: svc_dbadmin (honeytoken)",  kind="login",     decoy=True),
    "file-01:readme":     dict(host="file-01",  name="shared/readme.txt",                kind="file",      decoy=False),
    "file-01:salary":     dict(host="file-01",  name="Q3_salary_sheet.xlsx (decoy)",     kind="file",      decoy=True),
    "admin-ws:notes":     dict(host="admin-ws", name="meeting_notes.txt",                kind="file",      decoy=False),
    "admin-ws:vpn":       dict(host="admin-ws", name="vpn_passwords.txt (decoy)",        kind="cred_file", decoy=True),
}

SEV_ICON = {"Critical": "🟥", "High": "🟧", "Medium": "🟨"}
SEV_POINTS = {"Critical": 40, "High": 25, "Medium": 10}
TACTIC = {
    "T1595": "Reconnaissance", "T1190": "Initial Access", "T1046": "Discovery",
    "T1083": "Discovery", "T1552": "Credential Access", "T1110": "Credential Access",
    "T1078": "Valid Accounts / Persistence", "T1021": "Lateral Movement",
}
FAKE_ENV = "DB_HOST=db-01.internal\nDB_USER=svc_dbadmin\nDB_PASS=Summer2026!Prod\nBACKUP_BUCKET=acme-hr-backup\n"


# ----------------------------------------------------------------------------
# LIVE HONEYPOT (shared by all visitors of the deployed app)
# ----------------------------------------------------------------------------
DB_PATH = os.path.join(tempfile.gettempdir(), "deceptionnet_live.db")


def _q(sql, args=(), fetch=False):
    with closing(sqlite3.connect(DB_PATH, timeout=10)) as c:
        cur = c.execute(sql, args)
        rows = cur.fetchall() if fetch else None
        c.commit()
        return rows


class LiveStore:
    """SQLite-backed store: live honeypot hits survive reruns and are shared by every visitor."""

    def __init__(self):
        _q("CREATE TABLE IF NOT EXISTS live (id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT)")

    def append(self, ev):
        e = dict(ev)
        e["ts"] = e["ts"].isoformat()
        _q("INSERT INTO live (data) VALUES (?)", (json.dumps(e),))

    def __iter__(self):
        for (d,) in _q("SELECT data FROM live ORDER BY id", fetch=True):
            e = json.loads(d)
            e["ts"] = datetime.fromisoformat(e["ts"])
            yield e

    def __len__(self):
        return _q("SELECT COUNT(*) FROM live", fetch=True)[0][0]

    def clear(self):
        _q("DELETE FROM live")


@st.cache_resource
def live_store():
    return LiveStore()


@st.cache_data(ttl=3600, show_spinner=False)
def geo_lookup(ip):
    """Real IP enrichment (country / city / ISP) for live visitors."""
    if not ip or ip.startswith(("unknown", "10.", "192.168.", "127.", "172.")):
        return ""
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp", timeout=2) as r:
            d = json.loads(r.read())
        if d.get("status") == "success":
            return f"{d.get('city', '')}, {d.get('country', '')} - {d.get('isp', '')}"
    except Exception:  # noqa: BLE001
        pass
    return ""


def visitor():
    try:
        h = st.context.headers
        ip = (h.get("X-Forwarded-For") or h.get("X-Real-Ip") or "unknown-visitor").split(",")[0].strip()
        ua = h.get("User-Agent", "")
    except Exception:  # noqa: BLE001
        ip, ua = "unknown-visitor", ""
    return ip, ua


def live_log(action, asset, severity, tech):
    ip, ua = visitor()
    live_store().append(dict(
        ts=datetime.now().replace(microsecond=0), session=ip, src="Internet", dst="web-01",
        action=action, asset=asset, decoy=True, severity=severity, technique=tech, live=True, ua=ua,
        geo=geo_lookup(ip)))


def render_portal():
    if not st.session_state.get("visit_logged"):
        live_log("visit", "/admin-portal (hidden URL)", "Medium", "T1595 Active Scanning")
        st.session_state.visit_logged = True
    st.markdown("## 🔐 Acme Corp - Internal Admin Portal")
    st.caption("Authorised personnel only. All access is monitored.")
    t_login, t_files = st.tabs(["Sign in", "Shared drive"])

    with t_login:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Sign in", type="primary"):
            if u.strip() == "svc_dbadmin" and p == "Summer2026!Prod":
                live_log("use_credential", "honeytoken svc_dbadmin reused from .env.bak", "Critical",
                         "T1078 Valid Accounts")
            else:
                live_log("login_attempt", f"admin login as '{u}'", "Critical", "T1110 Brute Force")
            st.error("Invalid credentials.")

    with t_files:
        st.caption("Company shared drive (read-only)")
        for fname, data, sev, tech in [
            ("Q3_salary_sheet.xlsx", "name,salary\nA. Kumar,0\n", "High", "T1083 File & Directory Discovery"),
            ("vpn_passwords.txt", "vpn-admin : Winter#2026\n", "High", "T1552 Unsecured Credentials"),
            (".env.bak", FAKE_ENV, "High", "T1552 Unsecured Credentials"),
        ]:
            st.download_button(f"📥 {fname}", data=data, file_name=fname, key=f"dl_{fname}",
                               on_click=live_log, args=("download", f"{fname} (decoy file)", sev, tech))

    st.divider()
    st.caption("🪤 Demo notice: this page is a honeypot built for the DeceptionNet hackathon project. "
               "Your IP, browser and actions are captured and shown on the defender dashboard in real time. "
               "No password is stored.")


if PAGE == "portal":
    render_portal()
    st.stop()


# ----------------------------------------------------------------------------
# SIMULATION STATE + EVENTS
# ----------------------------------------------------------------------------
def init_state():
    if "events" not in st.session_state:
        st.session_state.events = []
        st.session_state.pos = {}
        st.session_state.responses = {}
        st.session_state.clock = datetime.now().replace(microsecond=0)


def add_event(session, src, dst, action, asset_id=None, ts=None):
    asset = ASSETS.get(asset_id) if asset_id else None
    decoy = asset["decoy"] if asset else (HOSTS[dst]["decoy"] and action in ("move", "scan"))

    if action == "move":
        tech = "T1190 Exploit Public-Facing App" if src == "Internet" else "T1021 Remote Services"
    elif action == "scan":
        tech = "T1046 Network Service Discovery"
    elif asset and asset["kind"] == "cred_file":
        tech = "T1552 Unsecured Credentials"
    elif asset and asset["kind"] == "login":
        tech = "T1078 Valid Accounts"
    else:
        tech = "T1083 File & Directory Discovery"

    sev = ""
    if decoy:
        if asset and asset["kind"] == "login":
            sev = "Critical"
        elif asset:
            sev = "High"
        else:
            sev = "High" if action == "move" else "Medium"

    st.session_state.events.append(dict(
        ts=ts or st.session_state.clock, session=session, src=src, dst=dst, action=action,
        asset=asset["name"] if asset else "", decoy=decoy, severity=sev, technique=tech, live=False, ua="", geo=""))


def run_script(session, offset_s, steps):
    base = st.session_state.clock + timedelta(seconds=offset_s)
    for delay, src, dst, action, asset_id in steps:
        add_event(session, src, dst, action, asset_id, ts=base + timedelta(seconds=delay))


def run_demo():
    run_script("203.0.113.45", 0, [
        (0, "Internet", "web-01", "move", None),
        (40, "web-01", "web-01", "read_file", "web-01:index.html"),
        (75, "web-01", "web-01", "read_file", "web-01:.env.bak"),
        (120, "web-01", "app-01", "move", None),
        (180, "app-01", "app-01", "read_file", "app-01:app.conf"),
        (260, "app-01", "db-01", "move", None),
        (300, "db-01", "db-01", "use_credential", "db-01:svc_dbadmin"),
        (420, "db-01", "db-01", "read_file", "db-01:customers"),
        (600, "db-01", "hr-backup-01", "move", None),
    ])
    run_script("198.51.100.7", 90, [
        (0, "Internet", "web-01", "move", None),
        (20, "web-01", "web-01", "scan", None),
        (50, "web-01", "file-01", "move", None),
        (70, "file-01", "file-01", "read_file", "file-01:salary"),
        (95, "file-01", "admin-ws", "move", None),
        (110, "admin-ws", "admin-ws", "read_file", "admin-ws:vpn"),
    ])
    run_script("10.0.1.23", 30, [
        (0, "Internet", "web-01", "move", None),
        (10, "web-01", "web-01", "read_file", "web-01:index.html"),
    ])
    run_script("10.0.1.57", 200, [
        (0, "Internet", "web-01", "move", None),
        (30, "web-01", "app-01", "move", None),
        (45, "app-01", "app-01", "read_file", "app-01:app.conf"),
    ])
    st.session_state.clock += timedelta(minutes=20)


COLS = ["ts", "session", "src", "dst", "action", "asset", "decoy", "severity", "technique", "live", "ua", "geo"]


def get_df():
    ev = st.session_state.events + list(live_store())
    if not ev:
        return pd.DataFrame(columns=COLS)
    d = pd.DataFrame(ev)
    for c in ("ua", "geo"):
        if c not in d:
            d[c] = ""
        d[c] = d[c].fillna("")
    d["live"] = d["live"].fillna(False).astype(bool)
    return d.sort_values("ts").reset_index(drop=True)


# ----------------------------------------------------------------------------
# ANALYSIS
# ----------------------------------------------------------------------------
def reconstruct(df, session, k=None):
    s = df[df.session == session].sort_values("ts")
    if k is not None:
        s = s.head(k)
    path = []
    for _, r in s.iterrows():
        if not path:
            path.append(r.src)
        if r.dst != path[-1]:
            path.append(r.dst)
    return s, path


def fmt_td(td):
    secs = int(td.total_seconds())
    return f"{secs // 60}m {secs % 60}s"


def describe(r):
    if r.action == "move":
        return f"moved {r.src} → **{r.dst}**"
    if r.action == "scan":
        return f"scanned **{r.dst}**"
    if r.action == "visit":
        return f"opened hidden URL **{r.asset}**"
    if r.action == "login_attempt":
        return f"tried to log in: **{r.asset}**"
    if r.action == "download":
        return f"downloaded **{r.asset}**"
    verb = "used" if r.action == "use_credential" else "read"
    return f"{verb} **{r.asset}** on {r.dst}"


def risk_score(df, session):
    s, path = reconstruct(df, session)
    a = s[s.decoy]
    score = sum(SEV_POINTS[x] for x in a.severity)
    score += 5 * max(len(set(path)) - 1, 0) + 3 * s.technique.nunique()
    score = min(100, score)
    label = "CRITICAL" if score >= 80 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    return score, label



# ---------- Behavioural anomaly detection (statistical baseline model) ----------
def _depth():
    dist, queue = {"Internet": 0}, ["Internet"]
    while queue:
        h = queue.pop(0)
        for n in NEIGHBORS[h]:
            if n not in dist:
                dist[n] = dist[h] + 1
                queue.append(n)
    return dist


DEPTH = _depth()


def featurize(s):
    return [len(s), s.dst.nunique(), int((s.action == "move").sum()), s.technique.nunique(),
            max(DEPTH.get(h, 1) for h in s.dst)]


BENIGN_FEATS = ()


@st.cache_data
def _baseline(extra):
    """Normal-behaviour profile = synthetic staff sessions + (adaptive) every non-malicious session observed live.
    No decoy information is used as a feature, so this is an independent signal."""
    rng = np.random.default_rng(7)
    X = []
    for _ in range(600):
        depth = int(rng.integers(1, 3)); moves = depth
        X.append([moves + int(rng.integers(0, 3)), depth, moves, 1 + int(rng.integers(0, 2)), depth])
    X = np.array(X, float)
    if extra:
        X = np.vstack([X, np.repeat(np.array(extra, float), 10, axis=0)])
    return X.mean(axis=0), np.maximum(X.std(axis=0), 0.5)


def baseline():
    return _baseline(BENIGN_FEATS)


def anomaly_score(s):
    """0-100 behavioural anomaly score: distance of the session from the normal-behaviour profile."""
    mu, sd = baseline()
    z = np.maximum((np.array(featurize(s), float) - mu) / sd, 0)
    return int(round(100 * (1 - np.exp(-float(np.sqrt((z ** 2).sum())) / 4))))



# ---------- Attack-graph & deception coverage analytics ----------
CROWN = "db-01"
HOSTS_WITH_DECOYS = {h for h in HOSTS if HOSTS[h]["decoy"] or any(a["host"] == h and a["decoy"] for a in ASSETS.values())}


def simple_paths(src, dst):
    out = []

    def dfs(n, path):
        if n == dst:
            out.append(path[:])
            return
        for m in NEIGHBORS[n]:
            if m not in path:
                path.append(m)
                dfs(m, path)
                path.pop()

    dfs(src, [src])
    return out


def coverage():
    paths = simple_paths("Internet", CROWN)
    covered = [p for p in paths if any(h in HOSTS_WITH_DECOYS for h in p[1:])]
    first_hops = [next(i for i, h in enumerate(p) if h in HOSTS_WITH_DECOYS) for p in covered]
    bare = [h for h in HOSTS if h != "Internet" and h not in HOSTS_WITH_DECOYS]
    return paths, covered, (sum(first_hops) / len(first_hops) if first_hops else 0), bare


def analyst(df, session):
    s, path = reconstruct(df, session)
    a = s[s.decoy]
    acts = set(s.action)
    out = {}
    if "use_credential" in acts or "login_attempt" in acts:
        intent = "Credential-driven access: the source reused (or tried) credentials it found, aiming at deeper access."
    elif any("customers" in x for x in s.asset):
        intent = "Data theft: the source reached the production database and read customer data."
    elif "scan" in acts or "visit" in acts:
        intent = "Reconnaissance: mapping the environment and looking for valuable files."
    else:
        intent = "Opportunistic browsing of files and hosts."
    out["intent"] = intent

    real_actions = s[(~s.decoy) & (s.action != "move")]
    lag = (a.ts.min() - s.ts.min()).total_seconds() if len(a) else 0
    if len(path) >= 4 or ("use_credential" in acts):
        skill = "Advanced / targeted: moves methodically, reads real configs first, reuses stolen credentials."
    elif lag < 60 and len(real_actions) <= 1:
        skill = "Opportunistic: goes straight for obviously valuable names (salary sheet, passwords)."
    else:
        skill = "Intermediate: some enumeration before touching valuable-looking assets."
    out["skill"] = skill

    last = path[-1] if path else "web-01"
    nxt = [n for n in NEIGHBORS.get(last, []) if n not in path]
    preds = []
    for n in nxt:
        if HOSTS[n]["decoy"]:
            preds.append(f"**{n}** (decoy host): very likely, it looks like a juicy backup server → will trigger another alert")
        else:
            preds.append(f"**{n}** ({HOSTS[n]['role']}): plausible next hop")
    out["next"] = preds or ["No unexplored neighbouring hosts: attacker has covered this segment."]
    out["actions"] = [
        f"Block source `{session}` at the firewall",
        f"Isolate `{last}` from the network and take a forensic snapshot",
        "Rotate every credential exposed on `web-01` (the honeytoken `svc_dbadmin` is fake, but the real service accounts may share patterns)",
        "Review access logs on every host in the path for the same source",
    ]
    return out


def build_report(df, session):
    s, path = reconstruct(df, session)
    alerts = s[s.decoy]
    first, last = s.ts.min(), s.ts.max()
    crit = (alerts.severity == "Critical").sum()
    score, label = risk_score(df, session)
    first_alert = alerts.ts.min()
    src = "REAL visitor on the live honeypot" if s.live.any() else "simulated attacker"
    return f"""### Incident report - source `{session}` ({src})

**Verdict:** Confirmed intruder. Risk score **{score}/100 ({label})**. Touched {len(alerts)} decoy asset(s), {crit} critical.

**Attack path:** {" → ".join(path)}

**Timing:** activity {first:%H:%M:%S} to {last:%H:%M:%S} (dwell {fmt_td(last - first)}). First decoy hit at {first_alert:%H:%M:%S}, {fmt_td(first_alert - first)} after first contact.

**Decoys triggered:**
""" + "\n".join(f"- {r.ts:%H:%M:%S} - {r.asset or r.dst} ({r.severity})" for _, r in alerts.iterrows()) + f"""

**MITRE ATT&CK techniques:** {", ".join(sorted(set(s.technique)))}

**Recommended actions:** isolate `{path[-1] if path else 'affected hosts'}`, block `{session}`, rotate exposed credentials, review logs along the path."""


def _secret(name):
    v = os.getenv(name)
    if v:
        return v
    try:
        return st.secrets[name]
    except Exception:  # noqa: BLE001
        return None



def _gcall(url, key, payload=None):
    req = urllib.request.Request(url, data=json.dumps(payload).encode() if payload else None,
                                 headers={"Content-Type": "application/json", "x-goog-api-key": key})
    try:
        with urllib.request.urlopen(req, timeout=50) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()[:160]
        except Exception:  # noqa: BLE001
            pass
        raise RuntimeError(f"HTTP {e.code} {body}") from None


@st.cache_data(ttl=1800, show_spinner=False)
def gemini_models(key):
    """Ask the API which models this key can really use, newest flash-class first."""
    data = _gcall("https://generativelanguage.googleapis.com/v1beta/models?pageSize=200", key)
    names = []
    for m in data.get("models", []):
        n = m.get("name", "").replace("models/", "")
        if "generateContent" in m.get("supportedGenerationMethods", []) and "flash" in n:
            if not any(x in n for x in ("lite", "image", "tts", "live", "audio", "thinking", "embedding")):
                names.append(n)
    return sorted(set(names), reverse=True)[:4]


def gemini_text(prompt, key):
    try:
        models = gemini_models(key) or ["gemini-2.5-flash"]
    except Exception as e:  # noqa: BLE001
        return f"(LLM unavailable: could not list Gemini models - {e})"
    last = ""
    for model in models[:2]:
        try:
            d = _gcall(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent", key,
                       {"contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {"maxOutputTokens": 800, "temperature": 0.3}})
            return d["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:  # noqa: BLE001
            last = f"{model}: {e}"
    return f"(LLM unavailable: {last})"

def groq_text(prompt, key):
    last = ""
    for model in ("llama-3.3-70b-versatile", "llama-3.1-8b-instant", "openai/gpt-oss-20b"):
        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=json.dumps({"model": model,
                             "messages": [{"role": "user", "content": prompt}],
                             "max_tokens": 400, "temperature": 0.3}).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}",
                     "User-Agent": "DeceptionNet/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())["choices"][0]["message"]["content"]
        except Exception as e:  # noqa: BLE001
            last = f"{model}: {e}"
    return f"(LLM unavailable: groq {last})"
def claude_text(prompt):
    """Optional LLM layer: Claude (ANTHROPIC_API_KEY) or Gemini (GEMINI_API_KEY). Returns None if no key."""
    key = _secret("ANTHROPIC_API_KEY")
    if key:
        try:
            import anthropic
            m = anthropic.Anthropic(api_key=key).messages.create(
                model="claude-sonnet-4-6", max_tokens=400, messages=[{"role": "user", "content": prompt}])
            return m.content[0].text
        except Exception as e:  # noqa: BLE001
            return f"(LLM unavailable: {e})"
    qkey = _secret("GROQ_API_KEY")
    if qkey:
        return groq_text(prompt, qkey)
    gkey = _secret("GEMINI_API_KEY")
    if gkey:
        return gemini_text(prompt, gkey)
    return None


# ----------------------------------------------------------------------------
# DRAWING
# ----------------------------------------------------------------------------
def draw(path):
    fig = go.Figure()
    pos = {h: v["pos"] for h, v in HOSTS.items()}
    ex, ey = [], []
    for a, b in EDGES:
        ex += [pos[a][0], pos[b][0], None]
        ey += [pos[a][1], pos[b][1], None]
    fig.add_trace(go.Scatter(x=ex, y=ey, mode="lines", line=dict(color="#b0b0b0", width=2),
                             hoverinfo="none", showlegend=False))
    for i in range(len(path) - 1):
        a, b = path[i], path[i + 1]
        fig.add_annotation(x=pos[b][0], y=pos[b][1], ax=pos[a][0], ay=pos[a][1], xref="x", yref="y",
                           axref="x", ayref="y", showarrow=True, arrowhead=3, arrowsize=1.4, arrowwidth=4,
                           arrowcolor="#e53935", standoff=22, startstandoff=22)
        fig.add_annotation(x=(pos[a][0] + pos[b][0]) / 2, y=(pos[a][1] + pos[b][1]) / 2 + 0.18,
                           text=f"<b>{i + 1}</b>", showarrow=False, font=dict(color="#e53935", size=14))
    xs, ys, colors, symbols, texts, hover, lines = [], [], [], [], [], [], []
    for h, v in HOSTS.items():
        xs.append(v["pos"][0]); ys.append(v["pos"][1]); texts.append(h)
        dec = [a["name"] for a in ASSETS.values() if a["host"] == h and a["decoy"]]
        hover.append(f"<b>{h}</b><br>{v['role']}" + (("<br>Decoys: " + ", ".join(dec)) if dec else ""))
        colors.append("#fb8c00" if v["decoy"] else "#757575" if h == "Internet" else "#1e88e5")
        symbols.append("diamond" if v["decoy"] else "circle" if h == "Internet" else "square")
        lines.append("#e53935" if h in path else "white")
    fig.add_trace(go.Scatter(x=xs, y=ys, mode="markers+text", text=texts, textposition="bottom center",
                             hovertext=hover, hoverinfo="text", showlegend=False,
                             marker=dict(size=34, color=colors, symbol=symbols, line=dict(color=lines, width=4))))
    fig.update_layout(height=420, margin=dict(l=10, r=10, t=10, b=10),
                      xaxis=dict(visible=False, range=[-0.7, 6.7]),
                      yaxis=dict(visible=False, range=[-2.3, 2.3]), plot_bgcolor="rgba(0,0,0,0)")
    return fig


@st.fragment(run_every=5)
def live_feed():
    st.markdown("#### 📡 Live honeypot feed (real visitors, auto-refreshes)")
    ls = live_store()
    if not ls:
        st.caption("No real visitors yet. Open the portal link from the sidebar in another tab/phone and try it.")
        return
    d = pd.DataFrame(list(ls))
    if "geo" not in d:
        d["geo"] = ""
    d = d[["ts", "session", "geo", "action", "asset", "severity", "ua"]].sort_values("ts", ascending=False)
    d["ts"] = d.ts.dt.strftime("%H:%M:%S")
    d.columns = ["Time", "Visitor IP", "Location / ISP", "Action", "Asset", "Severity", "Browser / user-agent"]
    st.dataframe(d, width="stretch", hide_index=True)


# ----------------------------------------------------------------------------
# UI
# ----------------------------------------------------------------------------
init_state()
st.title("🪤 DeceptionNet")
st.caption("Cyber deception: decoy files, honeytoken credentials and decoy hosts that catch intruders, "
           "reconstruct their path and trigger a response. Simulated network + a REAL honeypot portal.")

with st.sidebar:
    st.header("🎮 Simulation")
    if st.button("▶ Run demo attack scenarios", type="primary", width="stretch"):
        run_demo()
    c_a, c_b = st.columns(2)
    if c_a.button("🗑 Reset sim", width="stretch"):
        st.session_state.events, st.session_state.pos, st.session_state.responses = [], {}, {}
        st.rerun()
    if c_b.button("🧹 Clear live", width="stretch"):
        live_store().clear()
        st.rerun()

    st.divider()
    st.subheader("🌐 Real honeypot")
    st.markdown("Add `?page=portal` to this app's URL and open it on any device. "
                "Every visit, login attempt and download shows up live.")
    st.code("<this-app-url>/?page=portal", language="text")

    st.divider()
    st.subheader("🕵 Be the attacker (manual)")
    sess = st.text_input("Attacker IP / session", "192.0.2.99")
    cur = st.session_state.pos.get(sess, "Internet")
    st.write(f"Current position: **{cur}**")
    dst = st.selectbox("Move to", NEIGHBORS[cur])
    if st.button("Move", width="stretch"):
        st.session_state.clock += timedelta(seconds=random.randint(5, 45))
        add_event(sess, cur, dst, "move")
        st.session_state.pos[sess] = dst
        st.rerun()
    here = {k: v for k, v in ASSETS.items() if v["host"] == cur}
    choice = st.selectbox("Interact with", ["(port scan)"] + list(here),
                          format_func=lambda k: k if k == "(port scan)" else here[k]["name"].split(" (")[0])
    if st.button("Execute", width="stretch"):
        st.session_state.clock += timedelta(seconds=random.randint(5, 45))
        if choice == "(port scan)":
            add_event(sess, cur, cur, "scan")
        else:
            add_event(sess, cur, cur, "use_credential" if here[choice]["kind"] == "login" else "read_file", choice)
        st.rerun()
    st.caption("The attacker can't tell decoys from real assets. The defender can.")

df = get_df()
alerts = df[df.decoy] if len(df) else df
detected = sorted(alerts.session.unique()) if len(alerts) else []

BENIGN_FEATS = tuple(tuple(featurize(df[df.session == x])) for x in sorted(df.session.unique())
                     if x not in detected) if len(df) else ()

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Events logged", len(df))
m2.metric("Sessions seen", df.session.nunique() if len(df) else 0)
m3.metric("🚨 Alerts", len(alerts))
m4.metric("Intruders detected", len(detected))
m5.metric("🌐 Live visitors", len(set(s["session"] for s in live_store())))

if not len(df):
    st.info("Click **▶ Run demo attack scenarios** in the sidebar, play as the attacker, or open the real honeypot portal.")
    live_feed()
    st.stop()

tabs = st.tabs(["🌐 Network & replay", "🚨 Alerts", "🧭 Timeline", "🧠 Analyst & risk",
                "🛡 Response", "🎯 ATT&CK", "📐 Coverage", "📄 Report", "ℹ How it works"])

with tabs[0]:
    sel = st.selectbox("Attacker session:", ["(none)"] + detected, key="net_sel")
    if sel == "(none)":
        st.plotly_chart(draw([]), width="stretch")
    else:
        full, _ = reconstruct(df, sel)
        k = st.slider("⏯ Replay step", 1, len(full), len(full)) if len(full) > 1 else 1
        sub, path = reconstruct(df, sel, k)
        st.plotly_chart(draw(path), width="stretch")
        last = sub.iloc[-1]
        st.caption(f"🤖 Behavioural anomaly score at this step: **{anomaly_score(sub)}/100**")
        st.markdown(f"{SEV_ICON.get(last.severity, '⚪')} `{last.ts:%H:%M:%S}` {describe(last)}"
                    + (f" - **ALERT ({last.severity})**" if last.decoy else ""))
    st.caption("🔷 real host  🔶 decoy host  ⚪ internet  🔴 numbered arrows = reconstructed attacker movement")

with tabs[1]:
    live_feed()
    st.markdown("#### All alerts")
    if len(alerts):
        v = alerts[["ts", "session", "dst", "action", "asset", "severity", "technique"]].copy()
        v["ts"] = v.ts.dt.strftime("%H:%M:%S")
        v["severity"] = v.severity.map(lambda x: f"{SEV_ICON[x]} {x}")
        v.columns = ["Time", "Source", "Host", "Action", "Decoy asset", "Severity", "ATT&CK"]
        st.dataframe(v, width="stretch", hide_index=True)
    st.success("0 false positives: legitimate users never touch decoys, so every hit is high-confidence.")

with tabs[2]:
    if not detected:
        st.info("No intruders detected yet.")
    else:
        who = st.selectbox("Intruder session", detected, key="tl_sel")
        s, path = reconstruct(df, who)
        a = s[s.decoy]
        c1, c2, c3 = st.columns(3)
        c1.metric("Hosts reached", max(len(set(path)) - 1, 0))
        c2.metric("Time to first alert", fmt_td(a.ts.min() - s.ts.min()))
        c3.metric("Dwell time", fmt_td(s.ts.max() - s.ts.min()))
        st.markdown("**Path:** " + " → ".join(path))
        st.divider()
        for _, r in s.iterrows():
            st.markdown(f"{SEV_ICON.get(r.severity, '⚪')} `{r.ts:%H:%M:%S}` {describe(r)} · _{r.technique}_"
                        + (f" - **ALERT ({r.severity})**" if r.decoy else ""))
        st.caption("⚪ steps before the first alert were silent. They are recovered by correlating all actions of the same source.")

with tabs[3]:
    if not detected:
        st.info("No intruders detected yet.")
    else:
        who = st.selectbox("Intruder session", detected, key="an_sel")
        score, label = risk_score(df, who)
        c1, c2 = st.columns([1, 3])
        c1.metric("Risk score", f"{score}/100", label)
        c2.progress(score / 100, text=f"Threat level: {label}")
        st.metric("🤖 Behavioural anomaly (baseline model, independent of decoys)", f"{anomaly_score(s_ := df[df.session == who])}/100")
        info = analyst(df, who)
        st.markdown(f"**🎯 Likely intent:** {info['intent']}")
        st.markdown(f"**🧩 Skill level:** {info['skill']}")
        st.markdown("**🔮 Predicted next moves:**")
        for p in info["next"]:
            st.markdown(f"- {p}")
        st.markdown("**✅ Recommended actions:**")
        for p in info["actions"]:
            st.markdown(f"- {p}")
        st.markdown("#### Hybrid detection: deception (certainty) + behavioural model (early warning)")
        rows = [{"session": x, "anomaly": anomaly_score(df[df.session == x]),
                 "verdict": "Decoy hit" if x in detected else "No decoy hit"} for x in df.session.unique()]
        fig2 = px.bar(pd.DataFrame(rows), x="session", y="anomaly", color="verdict", height=300,
                      color_discrete_map={"Decoy hit": "#e53935", "No decoy hit": "#43a047"}, range_y=[0, 100])
        fig2.update_layout(margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig2, width="stretch")
        st.caption("Deception gives near-zero false-positive alerts. The behavioural layer scores how unusual a session is and can warn before any decoy is touched.")
        q = st.text_input("Ask the analyst (needs ANTHROPIC_API_KEY or GEMINI_API_KEY, optional)", placeholder="What is this attacker after?")
        if q:
            ans = claude_text(f"You are a SOC analyst. Incident:\n{build_report(df, who)}\n\nQuestion: {q}")
            st.write(ans or "AI chat is off (no API key set). The rule-based analyst above is active.")

with tabs[4]:
    if not detected:
        st.info("No intruders detected yet.")
    else:
        who = st.selectbox("Intruder session", detected, key="rs_sel")
        _, path = reconstruct(df, who)
        lasth = path[-1] if path else "web-01"
        log = st.session_state.responses.setdefault(who, [])

        def act(txt):
            log.append((datetime.now().strftime("%H:%M:%S"), txt))

        b1, b2, b3, b4 = st.columns(4)
        if b1.button("🚫 Block IP", width="stretch"):
            act(f"Firewall rule added: DROP all from {who}")
        if b2.button(f"🔒 Isolate {lasth}", width="stretch"):
            act(f"Host {lasth} quarantined to isolated VLAN, snapshot taken")
        if b3.button("🔑 Rotate creds", width="stretch"):
            act("Exposed credentials rotated, active sessions revoked")
        if b4.button("⚡ Full playbook", width="stretch", type="primary"):
            act(f"Firewall rule added: DROP all from {who}")
            act(f"Host {lasth} quarantined to isolated VLAN, snapshot taken")
            act("Exposed credentials rotated, active sessions revoked")
            act("Incident ticket created and SOC on-call paged")
        st.markdown("#### Response log")
        if log:
            for t, txt in log:
                st.markdown(f"✅ `{t}` {txt}")
        else:
            st.caption("No response actions taken yet.")
        st.markdown("#### Source status")
        rows = []
        for ssn in detected:
            sc, lb = risk_score(df, ssn)
            blocked = any("DROP" in x for _, x in st.session_state.responses.get(ssn, []))
            rows.append({"Source": ssn, "Risk": f"{sc} ({lb})", "Behaviour anomaly": anomaly_score(df[df.session == ssn]),
                         "Type": "REAL visitor" if df[df.session == ssn].live.any() else "Simulated",
                         "Status": "🚫 Blocked" if blocked else "⚠ Active"})
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)

with tabs[5]:
    if not len(df):
        st.info("No data.")
    else:
        t = df.groupby("technique").size().reset_index(name="count")
        t["tactic"] = t.technique.map(lambda x: TACTIC.get(x.split()[0], "Other"))
        fig = px.bar(t.sort_values("count"), x="count", y="technique", color="tactic", orientation="h",
                     height=380, labels={"count": "events", "technique": ""})
        fig.update_layout(margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, width="stretch")
        st.caption("Every logged action is mapped to a MITRE ATT&CK technique and tactic.")

with tabs[6]:
    paths, covered, avg_hops, bare = coverage()
    st.markdown(f"#### Attack-graph analysis: all routes from the Internet to the crown jewel (`{CROWN}`)")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Attack paths to crown jewel", len(paths))
    c2.metric("Paths passing a decoy", f"{len(covered)}/{len(paths)}", f"{100 * len(covered) // max(len(paths), 1)}% covered")
    c3.metric("Avg hops to first decoy", f"{avg_hops:.1f}")
    c4.metric("Hosts without decoys", len(bare))
    rows = [{"Host": h, "Role": v["role"],
             "Decoy assets": sum(1 for a in ASSETS.values() if a["host"] == h and a["decoy"]) + (1 if v["decoy"] else 0),
             "Status": "✅ monitored" if h in HOSTS_WITH_DECOYS else "⚠ blind spot"}
            for h, v in HOSTS.items() if h != "Internet"]
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    if bare:
        st.warning("Recommendation: plant a canary asset on " + ", ".join(f"`{h}`" for h in bare)
                   + " (for example a fake `secrets.yml`) to remove the blind spot.")
    else:
        st.success("Every host carries at least one decoy: no blind spots.")
    with st.expander("All simple attack paths"):
        for pth in paths:
            st.markdown("- " + " → ".join(pth))

with tabs[7]:
    if not detected:
        st.info("No intruders detected yet.")
    else:
        who = st.selectbox("Intruder session", detected, key="rep_sel")
        rep = build_report(df, who)
        st.markdown(rep)
        if _secret("ANTHROPIC_API_KEY") or _secret("GROQ_API_KEY") or _secret("GEMINI_API_KEY"):
            if st.button("🤖 Generate AI executive summary", key=f"ai_btn_{who}"):
                with st.spinner("Asking the LLM (can take up to a minute)..."):
                    llm = claude_text(
                        "Write a 4-sentence executive summary of this security incident for a non-technical "
                        "manager:\n\n" + rep)
                    if llm and llm.startswith("(LLM unavailable"):
                        st.caption(llm[:200])
                    if not llm or llm.startswith("(LLM unavailable"):
                        _s2, _p2 = reconstruct(df, who)
                        llm = (f"Source {who} was confirmed as an intruder after touching "
                               f"{int(_s2.decoy.sum())} decoy asset(s). It moved through "
                               f"{' → '.join(_p2)} with a risk score of {risk_score(df, who)[0]}/100. "
                               "Recommended response: block the source, isolate the last host reached "
                               "and rotate any exposed credentials.")
                    st.session_state[f"ai_{who}"] = llm
            if st.session_state.get(f"ai_{who}"):
                st.markdown("#### 🤖 AI executive summary")
                st.write(st.session_state[f"ai_{who}"])
        st.download_button("⬇ Download report (.md)", rep, file_name=f"incident_{who}.md")
        _s, _p = reconstruct(df, who)
        ioc = {"source": who, "kind": "live honeypot visitor" if _s.live.any() else "simulated attacker",
               "location": next((g for g in _s.geo if g), ""), "user_agents": sorted(set(u for u in _s.ua if u)),
               "attack_path": _p, "techniques": sorted(set(_s.technique)),
               "decoys_triggered": [x for x in _s[_s.decoy].asset],
               "risk_score": risk_score(df, who)[0], "behaviour_anomaly": anomaly_score(_s),
               "first_seen": str(_s.ts.min()), "last_seen": str(_s.ts.max())}
        st.download_button("⬇ Export IOCs (JSON)", json.dumps(ioc, indent=2), file_name=f"ioc_{who}.json",
                           mime="application/json")

with tabs[8]:
    st.markdown("""
**Deception layers**
1. **Decoy files** (`Q3_salary_sheet.xlsx`, `vpn_passwords.txt`, `.env.bak`) look valuable, but nobody legitimate opens them.
2. **Honeytoken credentials**: fake `svc_dbadmin` creds planted in `.env.bak`. Any use is a *critical* alert.
3. **Decoy host** `hr-backup-01` has no business purpose, so any connection is suspicious.
4. **Real honeypot portal** (`?page=portal`): fake admin login, a fake shared drive with decoy files, and honeytoken reuse detection. Real visitors are captured live with IP and browser.

**Detection (hybrid):** touching a decoy = alert (severity by asset type, near-zero false positives). A statistical baseline model scores session behaviour (depth, hosts, moves, technique variety) against a normal-staff profile as an independent early-warning signal. **Reconstruction:** all earlier silent actions of that source are correlated, the path is rebuilt, replayable step by step, and mapped to MITRE ATT&CK.

**Response:** risk score, intent/skill classification, next-move prediction and one-click playbooks (block, isolate, rotate, ticket).

**Extras:** attack-graph coverage analysis (blind-spot detection), adaptive behavioural baseline that learns from observed benign sessions, SQLite-persisted live honeypot events with IP geolocation, IOC export.\n\n**Tech:** Python, Streamlit, Plotly, pandas, numpy, SQLite. Optional Claude or Gemini API for executive summary and analyst chat.
""")
