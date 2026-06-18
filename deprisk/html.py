import json

_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>deprisk · {source_escaped}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: #0f172a; font-family: 'Courier New', monospace; color: #e2e8f0; overflow: hidden; }}
svg {{ width: 100vw; height: 100vh; display: block; }}
.link {{ stroke: #1e3a5f; stroke-opacity: 0.8; }}
.node-label {{ font-size: 10px; fill: #64748b; pointer-events: none; }}
.node-label-direct {{ font-size: 11px; fill: #94a3b8; pointer-events: none; }}
#tooltip {{
  position: fixed;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 6px;
  padding: 10px 14px;
  font-size: 12px;
  line-height: 1.7;
  pointer-events: none;
  display: none;
  max-width: 280px;
  z-index: 10;
}}
#legend {{
  position: fixed;
  top: 16px;
  right: 16px;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 8px;
  padding: 14px 18px;
  font-size: 11px;
  z-index: 10;
}}
.leg {{ display: flex; align-items: center; gap: 9px; margin: 5px 0; color: #94a3b8; }}
.dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
#header {{
  position: fixed;
  top: 18px;
  left: 18px;
  font-size: 12px;
  color: #475569;
  z-index: 10;
  letter-spacing: 0.04em;
}}
#truncated-warn {{
  position: fixed;
  bottom: 18px;
  left: 50%;
  transform: translateX(-50%);
  background: #7c2d12;
  border: 1px solid #c2410c;
  border-radius: 6px;
  padding: 6px 14px;
  font-size: 11px;
  color: #fed7aa;
  display: none;
  z-index: 10;
}}
</style>
</head>
<body>
<div id="header">deprisk · {source_escaped}</div>
<div id="tooltip"></div>
<div id="legend">
  <div style="margin-bottom:8px;font-weight:bold;color:#e2e8f0;font-size:12px">Risk</div>
  <div class="leg"><div class="dot" style="background:#dc2626"></div>CVE</div>
  <div class="leg"><div class="dot" style="background:#d97706"></div>Outdated</div>
  <div class="leg"><div class="dot" style="background:#475569"></div>Abandoned</div>
  <div class="leg"><div class="dot" style="background:#2563eb"></div>OK · direct</div>
  <div class="leg"><div class="dot" style="background:#60a5fa"></div>OK · transitive</div>
  <div class="leg"><div class="dot" style="background:#334155"></div>Unknown</div>
</div>
<div id="truncated-warn">Graph capped at 80 packages — some transitive deps omitted</div>
<svg id="graph"></svg>
<script src="https://d3js.org/d3.v7.min.js"></script>
<script>
const graphData = {graph_json};
const truncated  = {truncated};

if (truncated) document.getElementById('truncated-warn').style.display = 'block';

const RISK_COLOR = {{
  root:      '#7c3aed',
  vuln:      '#dc2626',
  outdated:  '#d97706',
  abandoned: '#475569',
  ok_direct: '#2563eb',
  ok_trans:  '#60a5fa',
  unknown:   '#334155',
}};

function nodeColor(d) {{
  if (d.id === '__root__') return RISK_COLOR.root;
  if (d.risk === 'vuln')      return RISK_COLOR.vuln;
  if (d.risk === 'outdated')  return RISK_COLOR.outdated;
  if (d.risk === 'abandoned') return RISK_COLOR.abandoned;
  if (d.risk === 'ok')        return d.is_direct ? RISK_COLOR.ok_direct : RISK_COLOR.ok_trans;
  return RISK_COLOR.unknown;
}}

function nodeRadius(d) {{
  if (d.id === '__root__') return 16;
  return d.is_direct ? 9 : 6;
}}

const nodes = graphData.nodes.map(n => ({{...n}}));
const links = graphData.edges.map(e => ({{source: e.from, target: e.to}}));

const svg    = d3.select('#graph');
const width  = window.innerWidth;
const height = window.innerHeight;
const tooltip = document.getElementById('tooltip');

const sim = d3.forceSimulation(nodes)
  .force('link', d3.forceLink(links).id(d => d.id).distance(d => d.source.id === '__root__' ? 160 : 100).strength(0.5))
  .force('charge', d3.forceManyBody().strength(-420))
  .force('center', d3.forceCenter(width / 2, height / 2))
  .force('collision', d3.forceCollide(d => nodeRadius(d) + 22));

const g = svg.append('g');

svg.call(
  d3.zoom().scaleExtent([0.15, 4]).on('zoom', e => g.attr('transform', e.transform))
);

const link = g.append('g')
  .selectAll('line')
  .data(links).join('line')
  .attr('class', 'link')
  .attr('stroke-width', d => d.source.id === '__root__' ? 1.5 : 1);

const node = g.append('g')
  .selectAll('g')
  .data(nodes).join('g')
  .call(d3.drag()
    .on('start', (e, d) => {{ if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }})
    .on('drag',  (e, d) => {{ d.fx = e.x; d.fy = e.y; }})
    .on('end',   (e, d) => {{ if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }}));

node.append('circle')
  .attr('r', nodeRadius)
  .attr('fill', nodeColor)
  .attr('stroke', '#0f172a')
  .attr('stroke-width', 2);

node.append('text')
  .attr('class', d => d.is_direct || d.id === '__root__' ? 'node-label-direct' : 'node-label')
  .attr('dx', d => nodeRadius(d) + 5)
  .attr('dy', 4)
  .text(d => d.id === '__root__' ? d.label : d.label);

node
  .on('mouseover', (e, d) => {{
    if (d.id === '__root__') return;
    let html = `<b style="color:#e2e8f0">${{d.label}}</b>`;
    if (d.pinned) html += `<br><span style="color:#64748b">pinned:&nbsp;</span><span style="color:#94a3b8">${{d.pinned}}</span>`;
    if (d.latest) html += `<br><span style="color:#64748b">latest:&nbsp;</span><span style="color:#94a3b8">${{d.latest}}</span>`;
    if (d.cves && d.cves.length) html += `<br><span style="color:#f87171">${{d.cves.join(', ')}}</span>`;
    html += `<br><span style="color:#475569">${{d.is_direct ? 'direct' : 'transitive'}}</span>`;
    tooltip.innerHTML = html;
    tooltip.style.display = 'block';
  }})
  .on('mousemove', e => {{
    tooltip.style.left = (e.clientX + 14) + 'px';
    tooltip.style.top  = (e.clientY - 10) + 'px';
  }})
  .on('mouseout', () => {{ tooltip.style.display = 'none'; }});

sim.on('tick', () => {{
  link
    .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
    .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
  node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
}});
</script>
</body>
</html>
"""


def export(graph_data: dict, source: str) -> str:
    safe_source = source.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
    return _TEMPLATE.format(
        source_escaped=safe_source,
        graph_json=json.dumps(graph_data),
        truncated="true" if graph_data.get("truncated") else "false",
    )
