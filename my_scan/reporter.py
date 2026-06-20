import json
import logging
import os
from collections import defaultdict
from typing import Dict, Any, List

from my_scan.models import ScanReport

logger = logging.getLogger("HTMLReporter")


class HTMLReporter:
    """Generates a premium, interactive HTML report with Chart.js visualizations."""

    def generate(self, report: ScanReport, attack_log_path: str, output_path: str) -> None:
        attack_logs = self._read_attack_logs(attack_log_path)
        html_content = self._build_html(report, attack_logs)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"Generated HTML report at {output_path}")

    def _read_attack_logs(self, log_path: str) -> List[Dict[str, Any]]:
        logs = []
        if not os.path.exists(log_path):
            return logs
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return logs

    def _build_html(self, report: ScanReport, attack_logs: List[Dict[str, Any]]) -> str:
        report_dict  = report.to_dict()
        vuln_count   = len(report.vulnerabilities)
        sev_break    = report_dict.get("severity_breakdown", {})
        crit_count   = sev_break.get("Critical", 0)
        high_count   = sev_break.get("High", 0)
        med_count    = sev_break.get("Medium", 0)
        low_count    = sev_break.get("Low", 0)

        # ── type breakdown for bar chart ──────────────────────────────────
        type_counts: Dict[str, int] = defaultdict(int)
        for v in report.vulnerabilities:
            type_counts[v.vulnerability_type.replace("potential_", "")] += 1
        type_labels = json.dumps(list(type_counts.keys()))
        type_data   = json.dumps(list(type_counts.values()))

        # top severity card class
        if crit_count > 0:
            vuln_card_cls = "critical"
        elif high_count > 0:
            vuln_card_cls = "high"
        elif vuln_count > 0:
            vuln_card_cls = "medium"
        else:
            vuln_card_cls = "success"

        # ── vulnerability rows ───────────────────────────────────────────
        if report.vulnerabilities:
            rows = ""
            for v in report.vulnerabilities:
                sev_cls = v.severity.lower()
                payload_safe = v.payload.replace("<", "&lt;").replace(">", "&gt;")
                evidence_safe = v.evidence.replace("<", "&lt;").replace(">", "&gt;")
                rows += f"""
                <tr>
                  <td><span class="badge {sev_cls}">{v.severity}</span></td>
                  <td><strong class="vuln-type">{v.vulnerability_type.upper().replace('_',' ')}</strong></td>
                  <td class="text-break"><span class="method-tag">{v.method}</span><br><span class="url-text">{v.url}</span></td>
                  <td><code>{v.parameter}</code></td>
                  <td class="text-break"><code class="payload-code">{payload_safe}</code><br>
                      <span class="evidence-text">{evidence_safe}</span></td>
                  <td>
                    <button class="exploit-btn" onclick='exploit(this, "{v.method}", "{v.url}", "{v.parameter}", {json.dumps(v.payload)})'>⚡ Exploit</button>
                  </td>
                </tr>"""
            vulns_content = f"""
            <table id="vulns-table">
              <thead><tr>
                <th>Severity</th><th>Type</th><th>Endpoint</th>
                <th>Parameter</th><th>Payload / Evidence</th>
                <th>Action</th>
              </tr></thead>
              <tbody>{rows}</tbody>
            </table>"""
        else:
            vulns_content = "<div class='empty-state'>🎉 No vulnerabilities found!</div>"

        # ── app-map rows ─────────────────────────────────────────────────
        if report.app_map and report.app_map.nodes:
            map_rows = ""
            for _, node in report.app_map.nodes.items():
                params_str = ", ".join(node.params.keys()) if node.params else "<em>None</em>"
                if node.body:
                    params_str += " <span class='body-tag'>+body</span>"
                map_rows += f"""
                <tr>
                  <td><span class="method-tag">{node.method}</span></td>
                  <td class="text-break url-text">{node.url}</td>
                  <td>{params_str}</td>
                  <td><code>{node.discovered_via}</code></td>
                  <td>{node.depth}</td>
                </tr>"""
            appmap_content = f"""
            <table>
              <thead><tr>
                <th>Method</th><th>URL</th><th>Parameters</th>
                <th>Discovered via</th><th>Depth</th>
              </tr></thead>
              <tbody>{map_rows}</tbody>
            </table>"""
        else:
            appmap_content = "<div class='empty-state'>No endpoints mapped.</div>"

        # ── attack logs rows ──────────────────────────────────────────────
        if attack_logs:
            log_rows = ""
            for log in attack_logs[:1500]:
                status = log.get("response_status", 0)
                if status >= 500:
                    sc = "status-500"
                elif status >= 400:
                    sc = "status-400"
                elif status >= 200:
                    sc = "status-200"
                else:
                    sc = ""
                payload_safe = str(log.get("payload", "")).replace("<", "&lt;").replace(">", "&gt;")
                log_rows += f"""
                <tr>
                  <td class="ts-cell">{log.get('timestamp','')}</td>
                  <td><strong>{log.get('vuln_type','')}</strong></td>
                  <td class="text-break">
                    <span class="method-tag">{log.get('method','')}</span>
                    <span class="url-text">{log.get('url','')}</span><br>
                    <span class="param-tag">param: <code>{log.get('parameter','')}</code></span>
                  </td>
                  <td class="text-break"><code class="payload-code">{payload_safe}</code></td>
                  <td><span class="{sc}">{status}</span><br>
                      <span class="latency-text">{log.get('response_latency_ms',0):.0f}ms</span></td>
                </tr>"""
            logs_content = f"""
            <p class="logs-note">Showing up to 1500 entries. Total: {len(attack_logs)} logged.</p>
            <table>
              <thead><tr>
                <th>Timestamp</th><th>Type</th><th>Target</th>
                <th>Payload</th><th>Status / Latency</th>
              </tr></thead>
              <tbody>{log_rows}</tbody>
            </table>"""
        else:
            logs_content = "<div class='empty-state'>No attack logs available.</div>"

        # ── full HTML ─────────────────────────────────────────────────────
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Scan Report — {report.target_url}</title>
  <meta name="description" content="DAST Security scan report for {report.target_url}">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    :root {{
      --bg:         #0d1117;
      --bg-panel:   #161b22;
      --bg-card:    #21262d;
      --bg-hover:   #30363d;
      --border:     #30363d;
      --text:       #e6edf3;
      --text-muted: #7d8590;
      --text-dim:   #484f58;

      --red:    #f85149;
      --orange: #d29922;
      --yellow: #e3b341;
      --blue:   #58a6ff;
      --green:  #3fb950;
      --purple: #a371f7;
      --cyan:   #39d353;

      --glow-red:    rgba(248,81,73,.18);
      --glow-blue:   rgba(88,166,255,.15);
      --glow-green:  rgba(63,185,80,.15);
      --glow-orange: rgba(210,153,34,.18);

      --radius: 8px;
      --radius-lg: 12px;
    }}

    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      font-family: 'Inter', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      line-height: 1.6;
    }}

    /* ── Sidebar nav ── */
    .layout {{ display: flex; min-height: 100vh; }}

    .sidebar {{
      width: 220px;
      background: var(--bg-panel);
      border-right: 1px solid var(--border);
      padding: 24px 0;
      position: fixed;
      top: 0; left: 0; bottom: 0;
      z-index: 100;
      display: flex;
      flex-direction: column;
    }}

    .sidebar-logo {{
      padding: 0 20px 24px;
      font-size: 1.1rem;
      font-weight: 700;
      color: var(--blue);
      letter-spacing: -0.5px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 16px;
    }}

    .sidebar-logo span {{ color: var(--text-muted); font-weight: 400; }}

    .nav-item {{
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 20px;
      color: var(--text-muted);
      cursor: pointer;
      font-size: 0.9rem;
      font-weight: 500;
      border-left: 3px solid transparent;
      transition: all .15s;
      user-select: none;
    }}
    .nav-item:hover {{ color: var(--text); background: var(--bg-hover); }}
    .nav-item.active {{
      color: var(--blue);
      border-left-color: var(--blue);
      background: rgba(88,166,255,.07);
    }}
    .nav-item .badge-count {{
      margin-left: auto;
      background: var(--bg-card);
      border: 1px solid var(--border);
      color: var(--text-muted);
      padding: 1px 7px;
      border-radius: 99px;
      font-size: 0.75rem;
    }}
    .nav-item.active .badge-count {{ color: var(--blue); border-color: var(--blue); }}

    /* ── Main content ── */
    .main {{
      margin-left: 220px;
      padding: 32px 40px;
      max-width: 1400px;
      width: 100%;
    }}

    .page-header {{
      margin-bottom: 32px;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--border);
    }}

    .page-header h1 {{
      font-size: 1.6rem;
      font-weight: 700;
      color: var(--text);
      display: flex;
      align-items: center;
      gap: 10px;
    }}

    .page-header .target-url {{
      font-size: 0.9rem;
      color: var(--text-muted);
      margin-top: 6px;
      font-family: 'JetBrains Mono', monospace;
    }}

    .scan-meta {{
      display: flex;
      gap: 24px;
      margin-top: 12px;
      font-size: 0.82rem;
      color: var(--text-muted);
    }}
    .scan-meta span {{ display: flex; align-items: center; gap: 5px; }}

    /* ── Summary cards ── */
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 36px;
    }}

    .card {{
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 20px;
      position: relative;
      overflow: hidden;
      transition: transform .2s, box-shadow .2s;
    }}
    .card:hover {{ transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,.4); }}

    .card::before {{
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
    }}
    .card.blue::before   {{ background: var(--blue); box-shadow: 0 0 12px var(--blue); }}
    .card.green::before  {{ background: var(--green); }}
    .card.orange::before {{ background: var(--orange); }}
    .card.red::before    {{ background: var(--red); box-shadow: 0 0 12px var(--red); }}
    .card.medium::before {{ background: var(--blue); }}
    .card.success::before {{ background: var(--green); }}
    .card.critical::before {{ background: var(--red); box-shadow: 0 0 16px var(--red); }}
    .card.high::before   {{ background: var(--orange); }}

    .card-label {{
      font-size: 0.75rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 8px;
    }}
    .card-value {{
      font-size: 2.4rem;
      font-weight: 700;
      line-height: 1;
      margin-bottom: 6px;
    }}
    .card.blue   .card-value {{ color: var(--blue); }}
    .card.green  .card-value {{ color: var(--green); }}
    .card.orange .card-value {{ color: var(--orange); }}
    .card.red    .card-value {{ color: var(--red); }}
    .card.success .card-value {{ color: var(--green); }}
    .card.medium  .card-value {{ color: var(--blue); }}
    .card.critical .card-value {{ color: var(--red); }}
    .card.high    .card-value {{ color: var(--orange); }}

    .card-sub {{
      font-size: 0.78rem;
      color: var(--text-muted);
    }}

    /* ── Charts section ── */
    .charts-row {{
      display: grid;
      grid-template-columns: 1fr 2fr;
      gap: 20px;
      margin-bottom: 32px;
    }}

    .chart-box {{
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 20px;
    }}
    .chart-box h3 {{
      font-size: 0.85rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 16px;
    }}
    .chart-box canvas {{ max-height: 220px; }}

    /* ── Tab content ── */
    .tab-content {{ display: none; }}
    .tab-content.active {{ display: block; }}

    /* ── Table panel ── */
    .panel {{
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      overflow: hidden;
      margin-bottom: 24px;
    }}

    .panel-header {{
      padding: 14px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }}
    .panel-header h2 {{
      font-size: 0.95rem;
      font-weight: 600;
      color: var(--text);
    }}

    /* Filter bar */
    .filter-bar {{
      padding: 12px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }}
    .filter-btn {{
      padding: 4px 12px;
      border-radius: 99px;
      border: 1px solid var(--border);
      background: transparent;
      color: var(--text-muted);
      font-size: 0.8rem;
      font-family: inherit;
      cursor: pointer;
      transition: all .15s;
    }}
    .filter-btn:hover {{ border-color: var(--blue); color: var(--blue); }}
    .filter-btn.active {{ background: rgba(88,166,255,.12); border-color: var(--blue); color: var(--blue); }}

    .search-input {{
      margin-left: auto;
      padding: 5px 12px;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      color: var(--text);
      font-family: inherit;
      font-size: 0.82rem;
      outline: none;
      width: 220px;
    }}
    .search-input:focus {{ border-color: var(--blue); }}

    .table-wrap {{ overflow-x: auto; }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.875rem;
    }}
    th {{
      padding: 11px 16px;
      background: var(--bg-card);
      color: var(--text-muted);
      font-weight: 600;
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: .5px;
      text-align: left;
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }}
    td {{
      padding: 11px 16px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    tbody tr {{ transition: background .1s; }}
    tbody tr:hover {{ background: var(--bg-card); }}
    tbody tr:last-child td {{ border-bottom: none; }}

    /* ── Badges ── */
    .badge {{
      display: inline-block;
      padding: 3px 9px;
      border-radius: 99px;
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .5px;
      white-space: nowrap;
    }}
    .badge.critical {{ background: var(--glow-red);    color: var(--red);    border: 1px solid var(--red); }}
    .badge.high      {{ background: var(--glow-orange); color: var(--orange); border: 1px solid var(--orange); }}
    .badge.medium    {{ background: var(--glow-blue);   color: var(--blue);   border: 1px solid var(--blue); }}
    .badge.low       {{ background: var(--glow-green);  color: var(--green);  border: 1px solid var(--green); }}

    /* ── Type & method tags ── */
    .method-tag {{
      display: inline-block;
      padding: 1px 7px;
      border-radius: 4px;
      font-size: 0.72rem;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
      background: rgba(88,166,255,.1);
      color: var(--blue);
      margin-right: 6px;
    }}
    .body-tag {{
      font-size: 0.7rem;
      background: rgba(210,153,34,.1);
      color: var(--yellow);
      padding: 1px 5px;
      border-radius: 3px;
    }}
    .param-tag {{ font-size: 0.78rem; color: var(--text-muted); }}
    .vuln-type {{ font-size: 0.82rem; color: var(--text); }}
    .url-text  {{ font-size: 0.78rem; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; word-break: break-all; }}
    .evidence-text {{ font-size: 0.78rem; color: var(--text-muted); }}
    .ts-cell {{ font-size: 0.75rem; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; white-space: nowrap; }}
    .latency-text {{ font-size: 0.78rem; color: var(--text-muted); }}

    /* Status codes */
    .status-200 {{ color: var(--green); font-weight: 600; }}
    .status-400 {{ color: var(--orange); font-weight: 600; }}
    .status-500 {{ color: var(--red); font-weight: 600; }}

    code, .payload-code {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      background: var(--bg-card);
      border: 1px solid var(--border);
      padding: 2px 6px;
      border-radius: 4px;
      word-break: break-all;
      color: var(--cyan);
    }}

    .exploit-btn {{
      padding: 6px 12px;
      background: rgba(248,81,73,.15);
      color: var(--red);
      border: 1px solid var(--red);
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.75rem;
      font-weight: 600;
      transition: all 0.2s;
      white-space: nowrap;
    }}
    .exploit-btn:hover {{
      background: var(--red);
      color: #fff;
    }}

    .empty-state {{
      text-align: center;
      padding: 60px 20px;
      color: var(--text-muted);
      font-size: 1.1rem;
    }}

    .logs-note {{
      padding: 10px 20px;
      font-size: 0.8rem;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border);
    }}

    #vulns-table tbody tr[data-sev] {{ cursor: default; }}

    .text-break {{ word-break: break-all; }}

    /* ── Scrollbar ── */
    ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
    ::-webkit-scrollbar-track {{ background: var(--bg); }}
    ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 99px; }}
    ::-webkit-scrollbar-thumb:hover {{ background: var(--text-dim); }}
  </style>
</head>
<body>
<div class="layout">

  <!-- ── Sidebar ── -->
  <nav class="sidebar">
    <div class="sidebar-logo">Scanner<span>/report</span></div>
    <div class="nav-item active" id="nav-overview" onclick="showTab('overview', this)">
      📊 Overview
    </div>
    <div class="nav-item" id="nav-vulns" onclick="showTab('vulns', this)">
      ⚠️ Vulnerabilities
      <span class="badge-count">{vuln_count}</span>
    </div>
    <div class="nav-item" id="nav-appmap" onclick="showTab('appmap', this)">
      🗺️ App Map
      <span class="badge-count">{report.endpoints_found}</span>
    </div>
    <div class="nav-item" id="nav-logs" onclick="showTab('logs', this)">
      📝 Attack Logs
      <span class="badge-count">{len(attack_logs)}</span>
    </div>
  </nav>

  <!-- ── Main ── -->
  <main class="main">
    <div class="page-header">
      <h1>Security Scan Report</h1>
      <div class="target-url">Target: {report.target_url}</div>
      <div class="scan-meta">
        <span>🕐 Duration: <strong>{report.duration_seconds}s</strong></span>
        <span>📅 Started: <strong>{report.scan_start}</strong></span>
        <span>✅ Status: <strong>{report.state}</strong></span>
      </div>
    </div>

    <!-- ── OVERVIEW TAB ── -->
    <div id="tab-overview" class="tab-content active">

      <!-- Summary Cards -->
      <div class="cards">
        <div class="card {vuln_card_cls}">
          <div class="card-label">Vulnerabilities</div>
          <div class="card-value">{vuln_count}</div>
          <div class="card-sub">
            <span style="color:var(--red)">{crit_count} Crit</span> &nbsp;
            <span style="color:var(--orange)">{high_count} High</span> &nbsp;
            <span style="color:var(--blue)">{med_count} Med</span> &nbsp;
            <span style="color:var(--green)">{low_count} Low</span>
          </div>
        </div>
        <div class="card blue">
          <div class="card-label">Endpoints Found</div>
          <div class="card-value">{report.endpoints_found}</div>
          <div class="card-sub">Mapped via crawler</div>
        </div>
        <div class="card orange">
          <div class="card-label">Attack Vectors</div>
          <div class="card-value">{report.attack_vectors_sent}</div>
          <div class="card-sub">Total payloads sent</div>
        </div>
        <div class="card green">
          <div class="card-label">Scan Duration</div>
          <div class="card-value">{report.duration_seconds}s</div>
          <div class="card-sub">Full scan completed</div>
        </div>
      </div>

      <!-- Charts -->
      <div class="charts-row">
        <div class="chart-box">
          <h3>Severity Breakdown</h3>
          <canvas id="pieChart"></canvas>
        </div>
        <div class="chart-box">
          <h3>Vulnerabilities by Type</h3>
          <canvas id="barChart"></canvas>
        </div>
      </div>

    </div><!-- /overview -->

    <!-- ── VULNERABILITIES TAB ── -->
    <div id="tab-vulns" class="tab-content">
      <div class="panel">
        <div class="panel-header">
          <h2>⚠️ Vulnerability Findings ({vuln_count})</h2>
        </div>
        <div class="filter-bar">
          <button class="filter-btn active" onclick="filterSev(this,'all')">All</button>
          <button class="filter-btn" onclick="filterSev(this,'critical')">Critical ({crit_count})</button>
          <button class="filter-btn" onclick="filterSev(this,'high')">High ({high_count})</button>
          <button class="filter-btn" onclick="filterSev(this,'medium')">Medium ({med_count})</button>
          <button class="filter-btn" onclick="filterSev(this,'low')">Low ({low_count})</button>
          <input class="search-input" type="search" placeholder="Search…" oninput="searchTable(this,'vulns-table')">
        </div>
        <div class="table-wrap">{vulns_content}</div>
      </div>
    </div>

    <!-- ── APP MAP TAB ── -->
    <div id="tab-appmap" class="tab-content">
      <div class="panel">
        <div class="panel-header"><h2>🗺️ Application Map ({report.endpoints_found} endpoints)</h2></div>
        <div class="table-wrap">{appmap_content}</div>
      </div>
    </div>

    <!-- ── ATTACK LOGS TAB ── -->
    <div id="tab-logs" class="tab-content">
      <div class="panel">
        <div class="panel-header"><h2>📝 Attack Logs</h2></div>
        {logs_content}
      </div>
    </div>

  </main>
</div><!-- /layout -->

<script>
  // ── Tab navigation ──────────────────────────────────────────────
  function showTab(name, el) {{
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    el.classList.add('active');
  }}

  // ── Severity filter ─────────────────────────────────────────────
  function filterSev(btn, sev) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const rows = document.querySelectorAll('#vulns-table tbody tr');
    rows.forEach(row => {{
      if (sev === 'all') {{ row.style.display = ''; return; }}
      const badge = row.querySelector('.badge');
      if (badge && badge.classList.contains(sev)) {{
        row.style.display = '';
      }} else {{
        row.style.display = 'none';
      }}
    }});
  }}

  // ── Table search ────────────────────────────────────────────────
  function searchTable(input, tableId) {{
    const q = input.value.toLowerCase();
    const rows = document.querySelectorAll('#' + tableId + ' tbody tr');
    rows.forEach(row => {{
      row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    }});
  }}

  // ── Chart.js ────────────────────────────────────────────────────
  const chartDefaults = {{
    color: '#7d8590',
    font: {{ family: 'Inter, system-ui', size: 12 }},
  }};
  Chart.defaults.color = chartDefaults.color;
  Chart.defaults.font  = chartDefaults.font;

  // Pie: severity breakdown
  new Chart(document.getElementById('pieChart'), {{
    type: 'doughnut',
    data: {{
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{{
        data: [{crit_count}, {high_count}, {med_count}, {low_count}],
        backgroundColor: [
          'rgba(248,81,73,.8)', 'rgba(210,153,34,.8)',
          'rgba(88,166,255,.8)', 'rgba(63,185,80,.8)'
        ],
        borderColor: ['#f85149','#d29922','#58a6ff','#3fb950'],
        borderWidth: 2,
        hoverOffset: 8,
      }}]
    }},
    options: {{
      cutout: '65%',
      plugins: {{
        legend: {{
          position: 'right',
          labels: {{ padding: 14, usePointStyle: true, pointStyleWidth: 10 }}
        }},
        tooltip: {{
          callbacks: {{
            label: ctx => ` ${{ctx.label}}: ${{ctx.parsed}} (${{Math.round(ctx.parsed / ({vuln_count} || 1) * 100)}}%)`
          }}
        }}
      }}
    }}
  }});

  // Bar: vuln types
  new Chart(document.getElementById('barChart'), {{
    type: 'bar',
    data: {{
      labels: {type_labels},
      datasets: [{{
        label: 'Count',
        data: {type_data},
        backgroundColor: 'rgba(88,166,255,.5)',
        borderColor: '#58a6ff',
        borderWidth: 1.5,
        borderRadius: 4,
        hoverBackgroundColor: 'rgba(88,166,255,.8)',
      }}]
    }},
    options: {{
      responsive: true,
      indexAxis: 'y',
      plugins: {{ legend: {{ display: false }} }},
      scales: {{
        x: {{
          grid: {{ color: 'rgba(48,54,61,.8)' }},
          ticks: {{ precision: 0 }}
        }},
        y: {{ grid: {{ display: false }} }}
      }}
    }}
  }});

  // ── Exploit Function ────────────────────────────────────────────
  function exploit(btn, method, url, parameter, payload) {{
    try {{
      // Disable button temporarily to prevent spam clicks
      const originalText = btn.innerHTML;
      btn.innerHTML = 'Executing...';
      btn.disabled = true;

      // Construct a form to submit
      const form = document.createElement('form');
      form.method = method === 'GET' ? 'GET' : 'POST';
      form.action = url;
      form.target = '_blank'; // Open in new tab

      // If it's a GET request, we append the payload to the URL params
      if (method === 'GET') {{
        const urlObj = new URL(url);
        urlObj.searchParams.set(parameter, payload);
        form.action = urlObj.toString();
      }} else {{
        // For POST requests, we add a hidden input for the parameter
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = parameter;
        input.value = payload;
        form.appendChild(input);
        
        // Try to handle potential JSON content types if we can guess it's a JSON endpoint
        // NOTE: Standard form submission always sends application/x-www-form-urlencoded or multipart/form-data.
        // For APIs expecting application/json, a native fetch might be required, but for XSS/SQLi in standard web apps,
        // form submission is visually verifiable.
      }}

      document.body.appendChild(form);
      form.submit();
      document.body.removeChild(form);

      setTimeout(() => {{
        btn.innerHTML = originalText;
        btn.disabled = false;
      }}, 1000);

    }} catch (e) {{
      alert('Error executing exploit: ' + e.message);
      btn.innerHTML = '⚡ Exploit';
      btn.disabled = false;
    }}
  }}
</script>
</body>
</html>"""
