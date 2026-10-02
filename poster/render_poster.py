from __future__ import annotations
from pathlib import Path
import html, re, shutil, subprocess, sys

repo = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]).resolve()
poster = repo / "poster"
brief = poster / "01_research_brief.md"
metrics_path = poster / "03_verified_metrics.md"
text = brief.read_text(encoding="utf-8", errors="replace")
metrics_text = metrics_path.read_text(encoding="utf-8", errors="replace") if metrics_path.exists() else ""

def clean(s: str) -> str:
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
    s = s.replace("**","").replace("`","").replace("\u2014","-").replace("\u2013","-").replace("\u2192","->")
    s = s.replace("\ufffd", "")
    return re.sub(r"\s+", " ", s).strip()

def sec(*names: str) -> str:
    for name in names:
        m = re.search(r"(?ms)^##+\s+" + re.escape(name) + r"\s*$\n(.*?)(?=^##+\s+|\Z)", text)
        if m:
            return m.group(1).strip()
    return ""

def items(block: str) -> list[str]:
    out=[]
    for line in block.splitlines():
        m=re.match(r"^\s*(?:[-*]|\d+\.)\s+(.*)", line)
        if m:
            v=clean(m.group(1))
            if v:
                out.append(v)
    return out

def strip_fences(s: str) -> str:
    s=re.sub(r"(?ms)\`\`\`.*?\`\`\`", "", s)
    return clean(s)

def esc(s: str) -> str:
    return html.escape(s, quote=True)

title = clean(sec("Academic Project Title","Project Title")) or repo.name.replace("-"," ").title()
subtitle = clean(sec("Subtitle"))
contribution = clean(sec("One-Sentence Contribution","Contribution","Research Contribution"))
methods = items(sec("Method","Methodology"))[:6]
evidence = items(sec("Current Verified Evidence","Verified Evidence","Evidence at Poster Snapshot + Claim Ledger"))[:7]
limits = items(sec("Honest Boundaries","Limitations","Limitations & Residual Risk","Not established by this repository"))[:6]
repro_block = sec("Reproducibility")
repro = strip_fences(repro_block)[:900]
repository = clean(sec("Repository")) or f"github.com/poojakira/{repo.name.replace('_readonly_','')}"

metrics=[]
headline_match=re.search(r"(?ms)^##+\s+Headline cards\s*$\n(.*?)(?=^##+\s+|\Z)", metrics_text)
if headline_match:
    for line in headline_match.group(1).splitlines():
        m=re.match(r"^\s*[-*]\s+(.+?)\s+(?:\u2014|\u2013|-)\s+(.+?)\s*$", line)
        if m:
            value,label=clean(m.group(1)),clean(m.group(2))
            if value and label:
                metrics.append((label,value))
for line in metrics_text.splitlines():
    if not line.strip().startswith("|") or "---" in line:
        continue
    cells=[clean(c) for c in line.strip().strip("|").split("|")]
    if len(cells)<2:
        continue
    k,v=cells[0],cells[1]
    if k.lower() in {"metric","current value","value","item","claim","series"}:
        continue
    if not k or not v or (k,v) in metrics:
        continue
    metrics.append((k,v))

primary_metrics=metrics[:4]
extra_metrics=metrics[4:8]
if extra_metrics:
    evidence=(evidence[:5] + [f"{k}: {v}" for k,v in extra_metrics])[:8]
if not methods:
    methods=["Inspect the trust boundary","Apply repository-specific security checks","Record reproducible evidence"]
if not evidence:
    evidence=["See README, verified metrics, tests, and CI for the current evidence snapshot."]
if not limits:
    limits=["No additional limitation text was found in the research brief. Consult the README before generalizing results."]
if not repro:
    repro="Clone the repository, check out the cited evidence snapshot, install documented dependencies, and run the verification commands in the README."

def bullets(xs: list[str], cls="") -> str:
    return '<ul class="'+cls+'">' + "".join("<li>"+esc(x)+"</li>" for x in xs) + "</ul>"

def title_class(s: str) -> str:
    if len(s) > 85: return "title xlong"
    if len(s) > 64: return "title long"
    return "title"

metric_cards=""
for k,v in primary_metrics:
    vc="metric-value"
    if len(v)>22: vc+=" tiny"
    elif len(v)>14: vc+=" small"
    metric_cards += f'<div class="metric"><div class="{vc}">{esc(v)}</div><div class="metric-label">{esc(k)}</div></div>'
if not metric_cards:
    metric_cards='<div class="metric"><div class="metric-value">Verified</div><div class="metric-label">Repository evidence</div></div>'

flow_nodes=""
for i,m in enumerate(methods,1):
    flow_nodes += f'<div class="flow-node"><div class="flow-index">{i:02d}</div><div>{esc(m)}</div></div>'

method_rows=""
for i,m in enumerate(methods,1):
    method_rows += f'<div class="method-row"><span>{i:02d}</span><div>{esc(m)}</div></div>'

evidence_chips=""
for i,e in enumerate(evidence[:6],1):
    evidence_chips += f'<div class="e-chip"><span>EV-{i:02d}</span><div>{esc(e)}</div></div>'

css = r"""
@page { size: 36in 48in; margin: 0; }
* { box-sizing: border-box; }
html, body { margin:0; width:36in; height:48in; font-family:"Segoe UI",Arial,sans-serif; background:#edf3f7; color:#13263a; }
.poster { width:36in; height:48in; overflow:hidden; background:#edf3f7; }
.hero { height:5.4in; padding:.72in 1.05in .55in; display:grid; grid-template-columns:2.3fr .7fr; gap:.65in; color:#fff;
  background:linear-gradient(125deg,#06182f 0%,#0b3657 58%,#086b7e 100%); border-bottom:.09in solid #23b0c9; }
.kicker { font-size:15pt; font-weight:800; letter-spacing:2.6px; color:#7ce8f5; text-transform:uppercase; }
.title { font-size:42pt; line-height:1.03; margin:.14in 0 .12in; font-weight:760; max-width:25in; overflow-wrap:anywhere; }
.title.long { font-size:36pt; } .title.xlong { font-size:31pt; }
.subtitle { font-size:20pt; line-height:1.2; color:#d6edf4; max-width:24in; }
.repo { margin-top:.20in; font-size:12.5pt; color:#98dce8; overflow-wrap:anywhere; }
.hero-side { align-self:center; border-left:2px solid rgba(128,225,241,.45); padding-left:.42in; }
.hero-side .label { font-size:11pt; text-transform:uppercase; letter-spacing:1.5px; color:#84e4f1; font-weight:800; }
.hero-side .value { margin-top:.08in; font-size:17pt; line-height:1.25; font-weight:700; }
.hero-side .note { margin-top:.15in; font-size:11.5pt; line-height:1.35; color:#c4e3eb; }

.metrics { height:3.6in; display:grid; grid-template-columns:repeat(4,1fr); gap:.28in; padding:.42in 1.05in; background:#f9fbfd; border-bottom:2px solid #d6e2ea; }
.metric { background:#fff; border:2px solid #cddde7; border-top:8px solid #168cad; border-radius:.14in; display:flex; flex-direction:column; align-items:center; justify-content:center; padding:.16in .22in; box-shadow:0 4px 12px rgba(5,35,55,.05); }
.metric-value { font-size:27pt; line-height:1.06; font-weight:850; color:#0b456f; text-align:center; overflow-wrap:anywhere; }
.metric-value.small { font-size:20pt; } .metric-value.tiny { font-size:15.5pt; }
.metric-label { margin-top:.08in; font-size:11.8pt; line-height:1.2; font-weight:700; color:#566b7d; text-align:center; }

.arch { height:11.5in; padding:.52in 1.05in; background:#071e34; color:#eefbff; border-bottom:.07in solid #1b9bb8; }
.section-kicker { font-size:11.5pt; font-weight:800; letter-spacing:1.5px; color:#6fe2f0; text-transform:uppercase; }
.arch h2 { margin:.06in 0 .28in; font-size:25pt; color:#fff; }
.arch-grid { display:grid; grid-template-columns:.72fr 2.28fr; gap:.45in; height:9.25in; }
.boundary { background:linear-gradient(180deg,#0d304c,#0c263e); border:2px solid #245f7a; border-radius:.16in; padding:.35in; display:grid; grid-template-rows:auto 1fr auto; }
.boundary-title { font-size:16pt; font-weight:800; color:#8ce8f5; }
.boundary-lanes { margin-top:.25in; display:grid; grid-template-rows:repeat(3,1fr); gap:.22in; }
.lane { border-left:7px solid #2cb1c8; background:#123a57; border-radius:.10in; padding:.26in; }
.lane strong { display:block; font-size:13pt; color:#fff; }
.lane p { margin:.08in 0 0; font-size:11.3pt; line-height:1.32; color:#c8e5ed; }
.boundary-note { font-size:10.5pt; line-height:1.35; color:#9ec9d4; }
.flow { display:grid; grid-template-columns:repeat(2,1fr); grid-auto-rows:1fr; gap:.28in; }
.flow-node { position:relative; border:2px solid #287897; background:linear-gradient(145deg,#102f4a,#11415d); border-radius:.15in; padding:.38in .35in .30in .93in; display:flex; align-items:center; font-size:14.2pt; line-height:1.3; font-weight:650; }
.flow-index { position:absolute; left:.25in; top:.25in; width:.46in; height:.46in; border-radius:50%; background:#29b7cc; color:#061c2c; display:flex; align-items:center; justify-content:center; font-size:12pt; font-weight:900; }
.flow-node::after { content:"→"; position:absolute; right:-.30in; top:50%; transform:translateY(-50%); color:#65d5e8; font-size:23pt; font-weight:900; z-index:4; }
.flow-node:nth-child(2n)::after { content:"↓"; right:50%; top:auto; bottom:-.34in; transform:translateX(50%); }
.flow-node:last-child::after { content:""; }

.middle { height:10.5in; padding:.48in 1.05in; display:grid; grid-template-columns:1.35fr .9fr; gap:.38in; background:#eef3f7; }
.panel { background:#fff; border:2px solid #d2dfe8; border-radius:.15in; box-shadow:0 5px 16px rgba(4,35,55,.06); padding:.36in .40in; overflow:hidden; }
.panel h2 { margin:0 0 .18in; font-size:21pt; color:#0b557e; border-bottom:4px solid #34a9c4; padding-bottom:.07in; }
.contrib { border-left:9px solid #22a1b9; background:#eaf8fb; height:3.05in; margin-bottom:.30in; }
.contrib p { font-size:15.2pt; line-height:1.36; font-weight:620; margin:.05in 0; }
.evidence-panel { height:6.1in; border-left:9px solid #159274; }
.evidence-grid { display:grid; grid-template-columns:1fr 1fr; gap:.18in; }
.e-chip { background:#f6fafc; border:1.5px solid #d5e3eb; border-radius:.10in; padding:.17in .19in; display:grid; grid-template-columns:.52in 1fr; gap:.10in; font-size:11.7pt; line-height:1.28; }
.e-chip span { font-size:9.5pt; font-weight:900; color:#0b7e90; letter-spacing:.3px; }
.method-panel { border-left:9px solid #1d7fb1; }
.method-row { min-height:.72in; display:grid; grid-template-columns:.52in 1fr; gap:.14in; align-items:center; background:#f5f9fc; border:1.5px solid #d1e0e9; border-radius:.10in; padding:.12in .17in; margin:.12in 0; font-size:12pt; line-height:1.28; font-weight:650; }
.method-row span { width:.40in; height:.40in; border-radius:50%; background:#157fa2; color:#fff; display:flex; align-items:center; justify-content:center; font-size:9.5pt; font-weight:900; }

.lower { height:13.5in; padding:.48in 1.05in .52in; display:grid; grid-template-columns:1.05fr 1fr .95fr; gap:.34in; background:#e8f0f5; border-top:2px solid #d4e1e8; }
.lower .panel { height:100%; }
.limits { border-left:9px solid #c27a2c; }
.repro { border-left:9px solid #4a7192; }
.provenance { border-left:9px solid #6c62a8; }
.panel ul { margin:.05in 0 0 .28in; padding:0; }
.panel li { font-size:12pt; line-height:1.35; margin:.10in 0; }
.repro p { font-family:"Cascadia Mono","Consolas",monospace; font-size:11.2pt; line-height:1.38; overflow-wrap:anywhere; white-space:normal; }
.prov-card { margin:.15in 0; background:#f7f9fc; border:1.5px solid #dae1e9; border-radius:.10in; padding:.18in; }
.prov-card strong { display:block; color:#4b438a; font-size:12pt; }
.prov-card p { margin:.06in 0 0; font-size:11.4pt; line-height:1.32; color:#415366; }

.footer { height:3.5in; padding:.60in 1.05in; background:#06182f; color:#d8e7ee; display:grid; grid-template-columns:2.5fr .8fr; gap:.45in; align-items:center; }
.footer h3 { margin:0 0 .08in; font-size:18pt; color:#80e2ef; }
.footer p { margin:0; font-size:11.8pt; line-height:1.36; }
.badge { justify-self:end; border:2px solid #3f9eb9; border-radius:.14in; padding:.20in .27in; text-align:center; color:#fff; font-size:11.5pt; font-weight:800; }
"""

prov = [
    ("Claim discipline","Metrics come from the repository's verified metrics and research brief."),
    ("Scope discipline","Benchmarks are reported only at their documented fixture, dataset, or test scope."),
    ("Reproduction","PDF and PNG are generated locally from committed evidence without paid services."),
]

doc='<!doctype html><html><head><meta charset="utf-8"><style>'+css+'</style></head><body><div class="poster">'
doc+=f'<section class="hero"><div><div class="kicker">Security Engineering Research Poster</div><h1 class="{title_class(title)}">{esc(title)}</h1><div class="subtitle">{esc(subtitle)}</div><div class="repo">{esc(repository)}</div></div><div class="hero-side"><div class="label">Evidence posture</div><div class="value">Verified, scoped, reproducible</div><div class="note">Claims are constrained to the repository evidence snapshot and stated limitations.</div></div></section>'
doc+='<section class="metrics">'+metric_cards+'</section>'
doc+='<section class="arch"><div class="section-kicker">System view</div><h2>Architecture and Threat-Control Flow</h2><div class="arch-grid"><div class="boundary"><div class="boundary-title">Trust Boundary</div><div class="boundary-lanes"><div class="lane"><strong>Input surface</strong><p>Data, models, requests, policies, or artifacts entering the tested path.</p></div><div class="lane"><strong>Control surface</strong><p>Repository-specific validation, analysis, and fail-closed checks.</p></div><div class="lane"><strong>Evidence surface</strong><p>Findings, metrics, tests, logs, or reproducible artifacts.</p></div></div><div class="boundary-note">This diagram describes the tested repository path, not a universal deployment guarantee.</div></div><div class="flow">'+flow_nodes+'</div></div></section>'
doc+='<section class="middle"><div><div class="panel contrib"><h2>Research Contribution</h2><p>'+esc(contribution or "Repository contribution documented in the research brief.")+'</p></div><div class="panel evidence-panel"><h2>Verified Evidence</h2><div class="evidence-grid">'+evidence_chips+'</div></div></div><div class="panel method-panel"><h2>Method and Control Path</h2>'+method_rows+'</div></section>'
prov_html="".join(f'<div class="prov-card"><strong>{esc(a)}</strong><p>{esc(b)}</p></div>' for a,b in prov)
doc+='<section class="lower"><div class="panel limits"><h2>Limitations and Residual Risk</h2>'+bullets(limits)+'</div><div class="panel repro"><h2>Reproducibility</h2><p>'+esc(repro)+'</p></div><div class="panel provenance"><h2>Evidence Provenance</h2>'+prov_html+'</div></section>'
doc+='<footer class="footer"><div><h3>Evidence-backed security engineering</h3><p>README, verified metrics, tests, CI, and committed artifacts remain authoritative. Poster layout emphasizes architecture, controls, evidence, limitations, and reproduction rather than unsupported efficacy claims.</p></div><div class="badge">36 x 48 in<br>PDF + PNG parity</div></footer>'
doc+='</div></body></html>'

html_path=poster/"_poster_render.html"
html_path.write_text(doc,encoding="utf-8")
browsers=[Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")]
browser=next((p for p in browsers if p.exists()),None)
if browser is None: raise SystemExit("browser not found")
pdf=poster/"poster_36x48.pdf"
png=poster/"poster.png"
profile=poster/"_poster_profile"
shutil.rmtree(profile,ignore_errors=True)
subprocess.run([str(browser),"--headless=new","--disable-gpu",f"--user-data-dir={profile}","--no-pdf-header-footer",f"--print-to-pdf={pdf}",html_path.resolve().as_uri()],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    import fitz
except Exception as exc:
    raise SystemExit(f"PyMuPDF required: {exc}")
d=fitz.open(pdf)
if len(d)!=1: raise SystemExit(f"poster must be one page, got {len(d)}")
page=d[0]
target_w=1800
scale=target_w/page.rect.width
pix=page.get_pixmap(matrix=fitz.Matrix(scale,scale),alpha=False)
pix.save(png)
d.close()
html_path.unlink(missing_ok=True)
shutil.rmtree(profile,ignore_errors=True)
if repo.name=="mcp-agent-security-gateway":
    shutil.copy2(pdf,repo/"MCP_Gateway_Poster.pdf")
print(repo.name, "pdf_bytes=",pdf.stat().st_size,"png_bytes=",png.stat().st_size)
