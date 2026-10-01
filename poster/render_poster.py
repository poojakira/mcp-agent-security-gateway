
from __future__ import annotations

import html
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POSTER = Path(__file__).resolve().parent
BRIEF = POSTER / "01_research_brief.md"
METRICS = POSTER / "03_verified_metrics.md"
OUT_PDF = POSTER / "poster_36x48.pdf"
OUT_PNG = POSTER / "poster.png"

BROWSERS = [
    Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
    Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
]

def clean_inline(text: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = text.replace("**", "").replace("__", "").replace(chr(96), "")
    return text.strip()

def parse_sections(md: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {"_lead": []}
    current = "_lead"
    in_code = False
    for raw in md.splitlines():
        line = raw.rstrip()
        if line.strip().startswith(chr(96) * 3):
            in_code = not in_code
            continue
        if in_code:
            continue
        m = re.match(r"^#{2,3}\s+(.+)$", line)
        if m:
            current = clean_inline(m.group(1))
            sections.setdefault(current, [])
            continue
        if line.startswith("# "):
            continue
        if line.startswith(">"):
            sections.setdefault("Evidence Status", []).append(clean_inline(line.lstrip("> ")))
            continue
        if line.strip():
            sections.setdefault(current, []).append(line.strip())
    return sections

def extract_title(sections: dict[str, list[str]], fallback: str) -> str:
    for key in ("Academic Project Title", "Project Title", "Title"):
        if sections.get(key):
            return clean_inline(" ".join(sections[key]))
    return fallback

def extract_subtitle(sections: dict[str, list[str]]) -> str:
    for key in ("Technical Subtitle", "Subtitle"):
        if sections.get(key):
            return clean_inline(" ".join(sections[key]))
    return ""

def block_html(lines: list[str]) -> str:
    parts: list[str] = []
    bullets: list[str] = []
    ordered: list[str] = []

    def flush():
        nonlocal bullets, ordered
        if bullets:
            parts.append("<ul>" + "".join(f"<li>{html.escape(clean_inline(x))}</li>" for x in bullets) + "</ul>")
            bullets = []
        if ordered:
            parts.append("<ol>" + "".join(f"<li>{html.escape(clean_inline(x))}</li>" for x in ordered) + "</ol>")
            ordered = []

    for raw in lines:
        if raw.startswith("- "):
            if ordered:
                flush()
            bullets.append(raw[2:])
        elif re.match(r"^\d+\.\s+", raw):
            if bullets:
                flush()
            ordered.append(re.sub(r"^\d+\.\s+", "", raw))
        else:
            flush()
            text = clean_inline(raw)
            if text:
                parts.append(f"<p>{html.escape(text)}</p>")
    flush()
    return "".join(parts)

def parse_metrics(md: str) -> list[tuple[str, str, str]]:
    rows=[]
    for line in md.splitlines():
        if not line.startswith("|") or "---" in line or "Metric" in line:
            continue
        cells=[clean_inline(c) for c in line.strip().strip("|").split("|")]
        if cells and (cells[0].lower() in {"item", "series"} or (len(cells) > 1 and cells[1].lower() == "value")):
            continue
        if len(cells) >= 3:
            rows.append((cells[0], cells[1], cells[2]))
        elif len(cells) == 2:
            rows.append((cells[0], cells[1], "Verified poster evidence"))
    return rows

def pick_section(sections: dict[str, list[str]], *names: str) -> list[str]:
    for name in names:
        if sections.get(name):
            return sections[name]
    return []

def main() -> int:
    brief = BRIEF.read_text(encoding="utf-8")
    metrics_md = METRICS.read_text(encoding="utf-8") if METRICS.exists() else ""
    sections = parse_sections(brief)
    metrics = parse_metrics(metrics_md)

    repo_lines = pick_section(sections, "Repository")
    repo = clean_inline(" ".join(repo_lines)) if repo_lines else ROOT.name
    title = extract_title(sections, ROOT.name)
    subtitle = extract_subtitle(sections)
    contribution = pick_section(sections, "One-Sentence Contribution", "Contribution")
    method = pick_section(sections, "Method")
    problem = pick_section(sections, "Problem and Threat Model", "Problem", "Threat Model")
    evidence = pick_section(
        sections,
        "Current Verified Evidence",
        "Verified Evidence",
        "Evidence at Poster Snapshot + Claim Ledger",
        "Evidence",
    )
    boundaries = pick_section(sections, "Honest Boundaries", "Boundaries", "Limitations")
    repro = pick_section(sections, "Reproducibility")
    sources = pick_section(sections, "Evidence Sources", "References")
    status = pick_section(sections, "Evidence Status")

    metric_cards = "".join(
        f"<div class='metric'><div class='mval'>{html.escape(value)}</div>"
        f"<div class='mname'>{html.escape(name)}</div><div class='mscope'>{html.escape(scope)}</div></div>"
        for name,value,scope in metrics[:8]
    )

    css = """
    @page { size: 36in 48in; margin: 0; }
    * { box-sizing: border-box; }
    html, body { margin:0; padding:0; background:#f4f7fb; font-family: Arial, Helvetica, sans-serif; color:#111827; }
    body { width:1800px; height:2400px; overflow:hidden; }
    .page { width:1800px; height:2400px; padding:78px 86px 64px; background:#f4f7fb; display:flex; flex-direction:column; }
    header { background:#0b1f33; color:white; padding:54px 64px 48px; border-radius:28px; }
    .repo { font-size:23px; letter-spacing:1.4px; text-transform:uppercase; opacity:.78; margin-bottom:14px; }
    h1 { font-size:66px; line-height:1.05; margin:0 0 16px; font-weight:800; }
    .subtitle { font-size:31px; line-height:1.25; color:#d9e8f5; margin:0; }
    .status { margin-top:20px; font-size:18px; color:#b9d3e7; }
    .metrics { display:grid; grid-template-columns:repeat(4,1fr); gap:20px; margin:28px 0; }
    .metric { background:white; border:2px solid #d8e1ea; border-radius:22px; padding:24px 25px; min-height:150px; box-shadow:0 4px 16px rgba(11,31,51,.05); }
    .mval { font-size:42px; font-weight:800; color:#0b5f8a; line-height:1; margin-bottom:8px; }
    .mname { font-size:19px; font-weight:700; line-height:1.15; }
    .mscope { font-size:15px; line-height:1.25; color:#556575; margin-top:7px; }
    .columns { display:grid; grid-template-columns:1fr 1fr 1fr; gap:26px; flex:1; min-height:0; }
    .col { display:flex; flex-direction:column; gap:22px; min-height:0; }
    section { background:white; border:2px solid #d8e1ea; border-radius:22px; padding:28px 30px 25px; }
    h2 { margin:0 0 14px; font-size:29px; color:#0b5f8a; line-height:1.1; }
    p, li { font-size:18px; line-height:1.38; margin:0 0 10px; }
    ul, ol { margin:0; padding-left:28px; }
    li { margin-bottom:8px; }
    .evidence p, .evidence li { font-size:17px; }
    footer { font-size:14px; color:#657789; margin-top:24px; text-align:center; }
    @media print {
      html, body { width:36in; height:48in; background:#f4f7fb; }
      body { overflow:hidden; }
      .page { width:36in; height:48in; padding:1.56in 1.72in 1.28in; }
      header { padding:1.08in 1.28in .96in; border-radius:.56in; }
      .repo { font-size:.46in; margin-bottom:.28in; }
      h1 { font-size:1.32in; margin-bottom:.32in; }
      .subtitle { font-size:.62in; }
      .status { margin-top:.4in; font-size:.36in; }
      .metrics { gap:.4in; margin:.56in 0; }
      .metric { border-width:.04in; border-radius:.44in; padding:.48in .5in; min-height:3in; }
      .mval { font-size:.84in; margin-bottom:.16in; }
      .mname { font-size:.38in; }
      .mscope { font-size:.3in; margin-top:.14in; }
      .columns { gap:.52in; }
      .col { gap:.44in; }
      section { border-width:.04in; border-radius:.44in; padding:.56in .6in .5in; }
      h2 { margin-bottom:.28in; font-size:.58in; }
      p, li { font-size:.36in; margin-bottom:.2in; }
      ul, ol { padding-left:.56in; }
      li { margin-bottom:.16in; }
      .evidence p, .evidence li { font-size:.34in; }
      footer { font-size:.28in; margin-top:.48in; }
    }
    """

    def sec(title_: str, lines: list[str], cls: str="") -> str:
        if not lines:
            return ""
        return f"<section class='{cls}'><h2>{html.escape(title_)}</h2>{block_html(lines)}</section>"

    body = f"""<!doctype html><html><head><meta charset="utf-8"><style>{css}</style></head><body>
    <main class="page">
      <header>
        <div class="repo">{html.escape(repo)}</div>
        <h1>{html.escape(title)}</h1>
        <p class="subtitle">{html.escape(subtitle)}</p>
        <div class="status">{html.escape(clean_inline(" ".join(status)))}</div>
      </header>
      <div class="metrics">{metric_cards}</div>
      <div class="columns">
        <div class="col">
          {sec("Contribution", contribution)}
          {sec("Problem & Threat Model", problem)}
          {sec("Method", method)}
        </div>
        <div class="col">
          {sec("Current Verified Evidence", evidence, "evidence")}
          {sec("Reproducibility", repro)}
        </div>
        <div class="col">
          {sec("Honest Boundaries", boundaries)}
          {sec("Evidence Sources & References", sources)}
        </div>
      </div>
      <footer>Generated from poster/01_research_brief.md and poster/03_verified_metrics.md. Rendered artifacts must not be edited independently of source evidence.</footer>
    </main></body></html>"""

    browser = next((p for p in BROWSERS if p.exists()), None)
    if not browser:
        raise SystemExit("Edge or Chrome not found")

    with tempfile.TemporaryDirectory(prefix="poster-render-") as td:
        td_path=Path(td)
        html_path=td_path/"poster.html"
        html_path.write_text(body,encoding="utf-8")
        url=html_path.resolve().as_uri()
        profile=td_path/"profile"
        subprocess.run([
            str(browser),"--headless=new","--disable-gpu","--hide-scrollbars",
            f"--user-data-dir={profile}",
            f"--print-to-pdf={OUT_PDF}",
            "--no-pdf-header-footer",
            url,
        ],check=True)
        subprocess.run([
            str(browser),"--headless=new","--disable-gpu","--hide-scrollbars",
            f"--user-data-dir={profile}",
            "--window-size=1800,2400",
            f"--screenshot={OUT_PNG}",
            url,
        ],check=True)

    if ROOT.name == "mcp-agent-security-gateway":
        (ROOT / "MCP_Gateway_Poster.pdf").write_bytes(OUT_PDF.read_bytes())

    print(f"rendered {OUT_PDF}")
    print(f"rendered {OUT_PNG}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
