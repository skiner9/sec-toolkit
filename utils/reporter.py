import json
import os
from datetime import datetime

def save_json(data: dict, filepath: str):
    os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)
    return filepath

def save_html(data: dict, filepath: str):
    target    = data.get("target", "Unknown")
    scan_time = data.get("scan_time", "")
    duration  = data.get("duration_seconds", 0)
    ports     = data.get("open_ports", [])
    total     = data.get("total_scanned", 0)
    os_guess  = data.get("os_guess", "Unknown")

    rows = ""
    for p in ports:
        rows += f"""
        <tr>
          <td>{p['port']}</td>
          <td>{p['protocol'].upper()}</td>
          <td><span class="badge">OPEN</span></td>
          <td>{p.get('service', 'unknown')}</td>
          <td class="banner">{p.get('banner', '—')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Scan Report — {target}</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e2e8f0; padding: 2rem; }}
  h1 {{ color: #a78bfa; font-size: 1.6rem; margin-bottom: 0.25rem; }}
  .meta {{ color: #64748b; font-size: 0.85rem; margin-bottom: 2rem; }}
  .stats {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .stat {{ background: #1e2130; border: 1px solid #2d3147; border-radius: 8px; padding: 1rem 1.5rem; }}
  .stat .val {{ font-size: 1.8rem; font-weight: 700; color: #a78bfa; }}
  .stat .lbl {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e2130; border-radius: 8px; overflow: hidden; }}
  th {{ background: #2d3147; padding: 0.75rem 1rem; text-align: left; font-size: 0.8rem; text-transform: uppercase; color: #94a3b8; }}
  td {{ padding: 0.7rem 1rem; border-top: 1px solid #2d3147; font-size: 0.9rem; }}
  .badge {{ background: #064e3b; color: #34d399; padding: 2px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; }}
  .banner {{ font-family: monospace; font-size: 0.8rem; color: #94a3b8; }}
</style>
</head>
<body>
  <h1>Port Scan Report</h1>
  <p class="meta">Target: <strong>{target}</strong> | Scanned: {scan_time}</p>
  <div class="stats">
    <div class="stat"><div class="val">{len(ports)}</div><div class="lbl">Open ports</div></div>
    <div class="stat"><div class="val">{total}</div><div class="lbl">Ports scanned</div></div>
    <div class="stat"><div class="val">{duration}s</div><div class="lbl">Duration</div></div>
  </div>
  <p style="margin-bottom:1rem;color:#94a3b8">OS guess: <strong style="color:#f9a8d4">{os_guess}</strong></p>
  <table>
    <thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Banner</th></tr></thead>
    <tbody>{rows if rows else '<tr><td colspan="5" style="text-align:center;color:#64748b;padding:2rem;">No open ports found</td></tr>'}</tbody>
  </table>
</body>
</html>"""

    os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
    with open(filepath, "w") as f:
        f.write(html)
    return filepath