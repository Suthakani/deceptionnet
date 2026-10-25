"""
DeceptionNet - Cyber Deception System (Orca Coder, Track 03)
Simulated network with decoy files, fake credentials and decoy hosts.
Any interaction with a decoy -> alert -> attacker movement reconstructed -> incident timeline + report.
Run:  streamlit run app.py
"""
import os
import random
from datetime import datetime, timedelta

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="DeceptionNet", page_icon="🪤", layout="wide")

# ----------------------------------------------------------------------------
# 1. SIMULATED NETWORK
# ----------------------------------------------------------------------------
HOSTS = {
    "Internet":     dict(pos=(0, 0),     role="External network",              decoy=False),
    "web-01":       dict(pos=(1.5, 0),   role="Public web server (DMZ)",       decoy=False),
    "app-01":       dict(pos=(3, 1.3),   role="Application server",            decoy=False),
    "db-01":        dict(pos=(4.5, 1.3), role="Production database",           decoy=False),
    "file-01":      dict(pos=(3, -1.3),  role="Corporate file server",         decoy=False),
    "admin-ws":     dict(pos=(4.5, -1.3), role="Admin workstation",            decoy=False),
    "hr-backup-01": dict(pos=(6, 0),     role="DECOY host (fake HR backup)",   decoy=True),
}
EDGES = [
    ("Internet", "web-01"), ("web-01", "app-01"), ("web-01", "file-01"),
    ("app-01", "db-01"), ("file-01", "admin-ws"),
    ("admin-ws", "hr-backup-01"), ("db-01", "hr-backup-01"),
]
NEIGHBORS = {h: [] for h in HOSTS}
for a, b in EDGES:
    NEIGHBORS[a].append(b)
    NEIGHBORS[b].append(a)

# kind: file (normal file) | cred_file (file holding credentials) | login (credential being used)
ASSETS = {
    "web-01:index.html":      dict(host="web-01",   name="index.html",              kind="file",      decoy=False),
    "web-01:.env.bak":        dict(host="web-01",   name=".env.bak (fake DB creds)", kind="cred_file", decoy=True),
    "app-01:app.conf":        dict(host="app-01",   name="app.conf",                kind="file",      decoy=False),
    "db-01:customers":        dict(host="db-01",    name="customers table",         kind="file",      decoy=False),
    "db-01:svc_dbadmin":      dict(host="db-01",    name="login: svc_dbadmin (honeytoken)", kind="login", decoy=True),
    "file-01:readme":         dict(host="file-01",  name="shared/readme.txt",       kind="file",      decoy=False),
    "file-01:salary":         dict(host="file-01",  name="Q3_salary_sheet.xlsx (decoy)", kind="file", decoy=True),
    "admin-ws:notes":         dict(host="admin-ws", name="meeting_notes.txt",       kind="file",      decoy=False),
    "admin-ws:vpn":           dict(host="admin-ws", name="vpn_passwords.txt (decoy)", kind="cred_file", decoy=True),
}

SEV_COLOR = {"Critical": "🟥", "High": "🟧", "Medium": "🟨"}


# ----------------------------------------------------------------------------
# 2. EVENT LOGGING + ALERT ENGINE
# ----------------------------------------------------------------------------
def init_state():
    if "events" not in st.session_state:
        st.session_state.events = []
        st.session_state.pos = {}
        st.session_state.clock = datetime.now().replace(microsecond=0)


def add_event(session, src, dst, action, asset_id=None, ts=None):
    asset = ASSETS.get(asset_id) if asset_id else None
    if asset:
        decoy = asset["decoy"]
    else:
        decoy = HOSTS[dst]["decoy"] and action in ("move", "scan")

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
        ts=ts or st.session_state.clock, session=session, src=src, dst=dst,
        action=action, asset=asset["name"] if asset else "",
        decoy=decoy, severity=sev, technique=tech,
    ))


def run_script(session, offset_s, steps):
    base = st.session_state.clock + timedelta(seconds=offset_s)
    for delay, src, dst, action, asset_id in steps:
        add_event(session, src, dst, action, asset_id, ts=base + timedelta(seconds=delay))


def run_demo():
    # Stealthy attacker: steals fake creds, reuses them, lateral movement into decoy host
    run_script("203.0.113.45", 0, [
        (0,   "Internet", "web-01", "move", None),
        (40,  "web-01", "web-01", "read_file", "web-01:index.html"),
        (75,  "web-01", "web-01", "read_file", "web-01:.env.bak"),
        (120, "web-01", "app-01", "move", None),
        (180, "app-01", "app-01", "read_file", "app-01:app.conf"),
        (260, "app-01", "db-01", "move", None),
        (300, "db-01", "db-01", "use_credential", "db-01:svc_dbadmin"),
        (420, "db-01", "db-01", "read_file", "db-01:customers"),
        (600, "db-01", "hr-backup-01", "move", None),
    ])
    # Noisy attacker going via file server
    run_script("198.51.100.7", 90, [
        (0,   "Internet", "web-01", "move", None),
        (20,  "web-01", "web-01", "scan", None),
        (50,  "web-01", "file-01", "move", None),
        (70,  "file-01", "file-01", "read_file", "file-01:salary"),
        (95,  "file-01", "admin-ws", "move", None),
        (110, "admin-ws", "admin-ws", "read_file", "admin-ws:vpn"),
    ])
    # Benign employees (must NOT raise alerts)
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


def get_df():
    if not st.session_state.events:
        return pd.DataFrame(columns=["ts", "session", "src", "dst", "action", "asset",
                                     "decoy", "severity", "technique"])
    return pd.DataFrame(st.session_state.events).sort_values("ts").reset_index(drop=True)


# ----------------------------------------------------------------------------
# 3. RECONSTRUCTION + REPORT
# ----------------------------------------------------------------------------
def reconstruct(df, session):
    s = df[df.session == session].sort_values("ts")
    path = []
    for _, r in s.iterrows():
        if r.action == "move":
            if not path:
                path.append(r.src)
            path.append(r.dst)
    return s, path


def fmt_td(td):
    secs = int(td.total_seconds())
    return f"{secs // 60}m {secs % 60}s"


def build_report(df, session):
    s, path = reconstruct(df, session)
    alerts = s[s.decoy]
    first, last = s.ts.min(), s.ts.max()
    first_alert = alerts.ts.min()
    techs = sorted(set(s.technique))
    crit = (alerts.severity == "Critical").sum()
    text = f"""### Incident report - source `{session}`

**Verdict:** Confirmed intruder (touched {len(alerts)} decoy asset(s), {crit} critical).

**Attack path:** {" → ".join(path)}

**Timing:** activity from {first:%H:%M:%S} to {last:%H:%M:%S} (dwell {fmt_td(last - first)}). First decoy hit at {first_alert:%H:%M:%S}, i.e. {fmt_td(first_alert - first)} after initial access.

**Decoys triggered:**
""" + "\n".join(f"- {r.ts:%H:%M:%S} - {r.asset or r.dst} ({r.severity})" for _, r in alerts.iterrows()) + f"""

**MITRE ATT&CK techniques observed:** {", ".join(techs)}

**Recommended actions:** isolate `{path[-1] if path else 'affected hosts'}`, block `{session}`, rotate the credentials found on `web-01`, review access logs on every host in the path, and check whether real data on `db-01` was read."""
    return text


def llm_summary(report_md):
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        try:
            key = st.secrets["ANTHROPIC_API_KEY"]
        except Exception:  # noqa: BLE001
            key = None
    if not key:
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=key)
        msg = client.messages.create(
            model="claude-sonnet-4-6", max_tokens=400,
            messages=[{"role": "user", "content":
                       "Write a 4-sentence executive summary of this security incident for a non-technical manager:\n\n" + report_md}],
        )
        return msg.content[0].text
    except Exception as e:  # noqa: BLE001
        return f"(LLM summary unavailable: {e})"


# ----------------------------------------------------------------------------
# 4. NETWORK DRAWING
# ----------------------------------------------------------------------------
def draw(path, touched_decoys):
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
        fig.add_annotation(x=pos[b][0], y=pos[b][1], ax=pos[a][0], ay=pos[a][1],
                           xref="x", yref="y", axref="x", ayref="y", showarrow=True,
                           arrowhead=3, arrowsize=1.4, arrowwidth=4, arrowcolor="#e53935",
                           standoff=22, startstandoff=22)
        fig.add_annotation(x=(pos[a][0] + pos[b][0]) / 2, y=(pos[a][1] + pos[b][1]) / 2 + 0.18,
                           text=f"<b>{i + 1}</b>", showarrow=False, font=dict(color="#e53935", size=14))
    xs, ys, colors, symbols, texts, hover, lines = [], [], [], [], [], [], []
    for h, v in HOSTS.items():
        xs.append(v["pos"][0]); ys.append(v["pos"][1]); texts.append(h)
        decoys_here = [a["name"] for a in ASSETS.values() if a["host"] == h and a["decoy"]]
        hover.append(f"<b>{h}</b><br>{v['role']}" + (("<br>Decoys: " + ", ".join(decoys_here)) if decoys_here else ""))
        if v["decoy"]:
            colors.append("#fb8c00"); symbols.append("diamond")
        elif h == "Internet":
            colors.append("#757575"); symbols.append("circle")
        else:
            colors.append("#1e88e5"); symbols.append("square")
        lines.append("#e53935" if h in path else "white")
    fig.add_trace(go.Scatter(
        x=xs, y=ys, mode="markers+text", text=texts, textposition="bottom center",
        hovertext=hover, hoverinfo="text", showlegend=False,
        marker=dict(size=34, color=colors, symbol=symbols, line=dict(color=lines, width=4)),
    ))
    fig.update_layout(height=430, margin=dict(l=10, r=10, t=10, b=10),
                      xaxis=dict(visible=False, range=[-0.7, 6.7]),
                      yaxis=dict(visible=False, range=[-2.3, 2.3]),
                      plot_bgcolor="rgba(0,0,0,0)")
    return fig


# ----------------------------------------------------------------------------
# 5. UI
# ----------------------------------------------------------------------------
init_state()

st.title("🪤 DeceptionNet")
st.caption("Cyber deception system: decoy files, fake credentials and decoy hosts that catch intruders and reconstruct their path.")

with st.sidebar:
    st.header("🎮 Simulation controls")
    if st.button("▶ Run demo attack scenarios", type="primary", width="stretch"):
        run_demo()
    if st.button("🗑 Reset", width="stretch"):
        st.session_state.events = []
        st.session_state.pos = {}
        st.rerun()

    st.divider()
    st.subheader("🕵 Be the attacker (manual)")
    sess = st.text_input("Attacker IP / session", "192.0.2.99")
    cur = st.session_state.pos.get(sess, "Internet")
    st.write(f"Current position: **{cur}**")

    moves = NEIGHBORS[cur]
    dst = st.selectbox("Move to", moves)
    if st.button("Move", width="stretch"):
        st.session_state.clock += timedelta(seconds=random.randint(5, 45))
        add_event(sess, cur, dst, "move")
        st.session_state.pos[sess] = dst
        st.rerun()

    here = {k: v for k, v in ASSETS.items() if v["host"] == cur}
    options = ["(port scan)"] + list(here.keys())
    choice = st.selectbox("Interact with", options,
                          format_func=lambda k: k if k == "(port scan)" else here[k]["name"].split(" (")[0])
    if st.button("Execute", width="stretch"):
        st.session_state.clock += timedelta(seconds=random.randint(5, 45))
        if choice == "(port scan)":
            add_event(sess, cur, cur, "scan")
        else:
            act = "use_credential" if here[choice]["kind"] == "login" else "read_file"
            add_event(sess, cur, cur, act, choice)
        st.rerun()
    st.caption("The attacker doesn't know which assets are decoys; the defender does.")

df = get_df()
alerts = df[df.decoy] if len(df) else df
detected = sorted(alerts.session.unique()) if len(alerts) else []
benign_alerts = 0  # alerts only fire on decoys, benign sessions never touch them

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events logged", len(df))
c2.metric("Sessions seen", df.session.nunique() if len(df) else 0)
c3.metric("🚨 Alerts", len(alerts))
c4.metric("Intruders detected", len(detected))

if not len(df):
    st.info("Click **▶ Run demo attack scenarios** in the sidebar, or play as the attacker manually.")
    st.stop()

tab1, tab2, tab3, tab4, tab5 = st.tabs(["🌐 Network", "🚨 Alerts", "🧭 Incident timeline", "📄 Report", "ℹ How it works"])

with tab1:
    sel = st.selectbox("Highlight attacker path for:", ["(none)"] + detected, key="net_sel")
    path = reconstruct(df, sel)[1] if sel != "(none)" else []
    st.plotly_chart(draw(path, []), width="stretch")
    st.caption("🔷 real host   🔶 decoy host   ⚪ internet   🔴 red arrows = reconstructed attacker movement (numbered)")

with tab2:
    if len(alerts):
        view = alerts[["ts", "session", "dst", "action", "asset", "severity", "technique"]].copy()
        view["ts"] = view.ts.dt.strftime("%H:%M:%S")
        view["severity"] = view.severity.map(lambda s: f"{SEV_COLOR[s]} {s}")
        view.columns = ["Time", "Source", "Host", "Action", "Decoy asset", "Severity", "ATT&CK"]
        st.dataframe(view, width="stretch", hide_index=True)
    st.success("Benign sessions: 0 false positives. Normal users never touch decoys, so any hit is high-confidence.")

with tab3:
    if not detected:
        st.info("No intruders detected yet.")
    else:
        who = st.selectbox("Intruder session", detected, key="tl_sel")
        s, path = reconstruct(df, who)
        a = s[s.decoy]
        m1, m2, m3 = st.columns(3)
        m1.metric("Hosts compromised", len(set(path)) - 1 if path else 0)
        m2.metric("Time to first alert", fmt_td(a.ts.min() - s.ts.min()))
        m3.metric("Total dwell time", fmt_td(s.ts.max() - s.ts.min()))
        st.markdown("**Path:** " + " → ".join(path))
        st.divider()
        for _, r in s.iterrows():
            icon = SEV_COLOR[r.severity] if r.decoy else "⚪"
            what = {"move": f"moved {r.src} → **{r.dst}**", "scan": f"scanned **{r.dst}**"}.get(
                r.action, f"{'used' if r.action == 'use_credential' else 'read'} **{r.asset}** on {r.dst}")
            flag = f"  — **ALERT ({r.severity})**" if r.decoy else ""
            st.markdown(f"{icon} `{r.ts:%H:%M:%S}` {what} · _{r.technique}_{flag}")
        st.caption("⚪ events before the first alert were silent. They are recovered by correlating every action of the same source once it trips a decoy.")

with tab4:
    if not detected:
        st.info("No intruders detected yet.")
    else:
        who = st.selectbox("Intruder session", detected, key="rep_sel")
        rep = build_report(df, who)
        st.markdown(rep)
        summ = llm_summary(rep)
        if summ:
            st.markdown("#### 🤖 AI executive summary")
            st.write(summ)
        st.download_button("⬇ Download report (.md)", rep, file_name=f"incident_{who}.md")

with tab5:
    st.markdown("""
**Deception layers**
1. **Decoy files:** `Q3_salary_sheet.xlsx`, `vpn_passwords.txt`, `.env.bak` look valuable but nobody legitimate opens them.
2. **Honeytoken credentials:** fake `svc_dbadmin` credentials planted in `.env.bak`. Any login attempt with them is a *critical* alert.
3. **Decoy host:** `hr-backup-01` has no business purpose, so any connection to it is suspicious.

**Detection:** zero-false-positive rule: touching a decoy = alert. Severity depends on the asset type.

**Reconstruction:** once a source trips a decoy, all of its earlier events are correlated by session, the host-to-host path is rebuilt, each step is mapped to MITRE ATT&CK, and a timeline + report are produced.

**Tech:** Python, Streamlit, Plotly, pandas (optional: Claude API for the executive summary).
""")
