"""Builds a single self-contained interactive HTML report (no network requests)."""
import json

COL = {"user": 0, "group": 1, "workstation": 2, "svc": 3, "server": 4, "crown": 5}
COLORS = {"user": "#60a5fa", "group": "#a78bfa", "workstation": "#34d399",
          "svc": "#fbbf24", "server": "#f472b6", "crown": "#ef4444"}
W, H = 1180, 760


def layout(g):
    cols = {}
    for n, d in g.nodes.items():
        cols.setdefault(COL[d["type"]], []).append(n)
    order = {c: sorted(v) for c, v in cols.items()}
    nbrs = {n: [] for n in g.nodes}
    for e in g.edges:
        nbrs[e["src"]].append(e["dst"]); nbrs[e["dst"]].append(e["src"])
    pos = {}

    def place():
        for c, lst in order.items():
            x = 70 + c * (W - 140) / 5
            for i, n in enumerate(lst):
                pos[n] = (x, 40 + (i + 0.5) * (H - 80) / len(lst))
    place()
    for _ in range(6):
        for c in sorted(order):
            def key(n):
                ys = [pos[m][1] for m in nbrs[n] if COL[g.nodes[m]["type"]] != c]
                return sum(ys) / len(ys) if ys else pos[n][1]
            order[c] = sorted(order[c], key=key)
        place()
    return pos


def write_html(g, res, path):
    pos = layout(g)
    nodes = [{"id": n, "type": d["type"], "entry": d["entry"], "target": d["target"],
              "x": round(pos[n][0], 1), "y": round(pos[n][1], 1), "color": COLORS[d["type"]]}
             for n, d in g.nodes.items()]
    from attackgraph import EDGE_TYPES
    edges = [{"id": e["id"], "s": e["src"], "d": e["dst"], "t": e["type"], "c": e["control"],
              "w": EDGE_TYPES[e["type"]][0], "why": EDGE_TYPES[e["type"]][1].format(a=e["src"], b=e["dst"])} for e in g.edges]
    controls = [{"id": k, **v} for k, v in g.controls.items()]
    data = {"nodes": nodes, "edges": edges, "controls": controls,
            "optimal": res["optimal_cut"]["controls"], "greedy": res["greedy_cut"]["controls"],
            "W": W, "H": H}
    html = TEMPLATE.replace("__DATA__", json.dumps(data))
    open(path, "w").write(html)


TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>AttackGraph</title>
<style>
 body{margin:0;font-family:Segoe UI,Helvetica,Arial,sans-serif;background:#0b1020;color:#e5e7eb;display:flex;height:100vh}
 #side{width:340px;padding:14px;overflow:auto;background:#111827;border-right:1px solid #1f2937;box-sizing:border-box}
 h1{font-size:18px;margin:0 0 4px} h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:#9ca3af;margin:16px 0 6px}
 .sub{font-size:12px;color:#9ca3af}
 .ctl{display:flex;gap:8px;align-items:flex-start;font-size:13px;padding:6px 0;border-bottom:1px solid #1f2937}
 .cost{margin-left:auto;background:#1f2937;border-radius:8px;padding:1px 8px;font-size:12px;white-space:nowrap}
 button{background:#2563eb;border:0;color:#fff;padding:6px 10px;border-radius:6px;cursor:pointer;margin:2px 4px 2px 0;font-size:12px}
 button.alt{background:#374151}
 .stat{display:flex;justify-content:space-between;font-size:13px;padding:3px 0}
 .yes{color:#f87171;font-weight:600}.no{color:#4ade80;font-weight:600}
 #main{flex:1;position:relative} svg{width:100%;height:100%}
 #tip{position:absolute;left:12px;bottom:12px;max-width:520px;background:#111827cc;border:1px solid #374151;border-radius:8px;padding:8px 10px;font-size:12px;min-height:18px}
 @media(max-width:800px){body{flex-direction:column}#side{width:100%;height:46vh;border-right:0;border-bottom:1px solid #1f2937}#main{height:54vh;flex:none}}
 .legend span{display:inline-block;margin-right:10px;font-size:11px}
 .dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:4px}
</style></head><body>
<div id="side">
 <h1>AttackGraph</h1>
 <div class="sub">Synthetic enterprise. An edge A &rarr; B means: whoever controls A can gain control of B through that privilege transition. A model, not a scan of any real network.</div>
 <h2>Exposure</h2><div id="stats"></div>
 <h2>Cheapest attack path</h2><div id="paths" class="sub"></div>
 <h2>Fixes (tick to apply)</h2>
 <div id="ctls"></div>
 <div style="margin-top:8px"><button id="bOpt">Apply optimal set</button><button id="bGr" class="alt">Apply greedy set</button><button id="bNone" class="alt">Reset</button></div>
 <div class="sub" id="cost" style="margin-top:6px"></div>
 <h2>Legend</h2><div class="legend" id="legend"></div>
 <div class="sub" style="margin-top:6px">Red edges lie on an attack path (reachable from a phishable entry, leading to a crown-jewel asset). Dashed edges are removed by a ticked fix. Hover an edge for the reason.</div>
</div>
<div id="main"><div id="zoom" style="position:absolute;right:12px;top:12px;z-index:2"><button id="zi">+</button><button id="zo" class="alt">&minus;</button><button id="zr" class="alt">Fit</button></div><svg id="svg" viewBox="0 0 __W__ __H__" style="touch-action:none"></svg><div id="tip">Hover an edge or node.</div></div>
<script>
const D=__DATA__;
const NS="http://www.w3.org/2000/svg";
const svg=document.getElementById("svg");
const byId={};D.nodes.forEach(n=>byId[n.id]=n);
const fixed=new Set();
function active(){return D.edges.filter(e=>!(e.c&&fixed.has(e.c)));}
function analyse(){
  const act=active(),adj={},radj={};
  D.nodes.forEach(n=>{adj[n.id]=[];radj[n.id]=[];});
  act.forEach(e=>{adj[e.s].push(e);radj[e.d].push(e);});
  const entries=D.nodes.filter(n=>n.entry).map(n=>n.id),targets=D.nodes.filter(n=>n.target).map(n=>n.id);
  const fwd=new Set(entries),q=[...entries];
  while(q.length){const u=q.shift();adj[u].forEach(e=>{if(!fwd.has(e.d)){fwd.add(e.d);q.push(e.d);}});}
  const bwd=new Set(targets),q2=[...targets];
  while(q2.length){const u=q2.shift();radj[u].forEach(e=>{if(!bwd.has(e.s)){bwd.add(e.s);q2.push(e.s);}});}
  const onPath=new Set();act.forEach(e=>{if(fwd.has(e.s)&&bwd.has(e.d)&&fwd.has(e.d))onPath.add(e.id);});
  // simple paths up to 8 hops entry -> target
  let count=0;const cap=200000;let capped=false;
  function dfs(u,seen,h){if(capped)return;if(byId[u].target){count++;if(count>=cap)capped=true;return;}
    if(h==8)return;adj[u].forEach(e=>{if(bwd.has(e.d)&&!seen.has(e.d)){seen.add(e.d);dfs(e.d,seen,h+1);seen.delete(e.d);}});}
  entries.forEach(s=>{if(bwd.has(s))dfs(s,new Set([s]),0);});
  return {fwd,onPath,count,capped,exposed:targets.filter(t=>fwd.has(t))};
}
function cheapest(target){
  const act=active(),adj={};D.nodes.forEach(n=>adj[n.id]=[]);act.forEach(e=>adj[e.s].push(e));
  const dist={},prev={};const q=[];D.nodes.filter(n=>n.entry).forEach(n=>{dist[n.id]=0;q.push([0,n.id]);});
  while(q.length){q.sort((a,b)=>a[0]-b[0]);const [d,u]=q.shift();if(d>dist[u])continue;if(u==target)break;
    adj[u].forEach(e=>{const nd=d+e.w;if(dist[e.d]===undefined||nd<dist[e.d]){dist[e.d]=nd;prev[e.d]=e;q.push([nd,e.d]);}});}
  if(dist[target]===undefined)return null;const p=[];let n=target;while(prev[n]){p.push(prev[n]);n=prev[n].s;}return {cost:dist[target],path:p.reverse()};}
function el(tag,attrs,parent){const e=document.createElementNS(NS,tag);for(const k in attrs)e.setAttribute(k,attrs[k]);(parent||svg).appendChild(e);return e;}
const defs=el("defs",{});
const mk=el("marker",{id:"ah",viewBox:"0 0 10 10",refX:"9",refY:"5",markerWidth:"6",markerHeight:"6",orient:"auto-start-reverse"},defs);
el("path",{d:"M0 0L10 5L0 10z",fill:"#ef4444"},mk);
const mg=el("marker",{id:"ag",viewBox:"0 0 10 10",refX:"9",refY:"5",markerWidth:"5",markerHeight:"5",orient:"auto-start-reverse"},defs);
el("path",{d:"M0 0L10 5L0 10z",fill:"#374151"},mg);
const tip=document.getElementById("tip");
const edgeEls={};
D.edges.forEach(e=>{const a=byId[e.s],b=byId[e.d];
  const p=el("line",{x1:a.x,y1:a.y,x2:b.x,y2:b.y,"stroke-width":1,stroke:"#374151","marker-end":"url(#ag)"});
  p.addEventListener("mouseenter",()=>{tip.textContent=e.s+" \u2192 "+e.d+" ["+e.t+"]: "+e.why+(e.c?" (fix: "+e.c+")":" (no fix modelled)");});
  edgeEls[e.id]=p;});
D.nodes.forEach(n=>{const g=el("g",{});
  const c=el("circle",{cx:n.x,cy:n.y,r:n.target?9:(n.entry?7:5),fill:n.color,stroke:n.entry?"#fff":(n.target?"#fff":"none"),"stroke-width":2},g);
  const t=el("text",{x:n.x+(n.type=="crown"?-12:8),y:n.y+3,"font-size":9,fill:"#cbd5e1","text-anchor":n.type=="crown"?"end":"start"},g);t.textContent=n.id;
  g.addEventListener("mouseenter",()=>{tip.textContent=n.id+" ("+n.type+")"+(n.entry?" - phishable entry point":"")+(n.target?" - crown-jewel asset":"");});
  n.el=c;});
function render(){
  const r=analyse();
  D.edges.forEach(e=>{const p=edgeEls[e.id];const removed=e.c&&fixed.has(e.c);
    if(removed){p.setAttribute("stroke","#6b7280");p.setAttribute("stroke-dasharray","3 3");p.setAttribute("stroke-width",1);p.setAttribute("opacity",".5");p.setAttribute("marker-end","url(#ag)");}
    else if(r.onPath.has(e.id)){p.setAttribute("stroke","#ef4444");p.removeAttribute("stroke-dasharray");p.setAttribute("stroke-width",2);p.setAttribute("opacity","1");p.setAttribute("marker-end","url(#ah)");}
    else{p.setAttribute("stroke","#374151");p.removeAttribute("stroke-dasharray");p.setAttribute("stroke-width",1);p.setAttribute("opacity",".45");p.setAttribute("marker-end","url(#ag)");}});
  D.nodes.forEach(n=>{n.el.setAttribute("opacity",(r.fwd.has(n.id)||n.entry)?"1":".5");});
  const s=document.getElementById("stats");
  const rows=D.nodes.filter(n=>n.target).map(n=>'<div class="stat"><span>'+n.id+'</span><span class="'+(r.fwd.has(n.id)?"yes":"no")+'">'+(r.fwd.has(n.id)?"EXPOSED":"not reachable")+'</span></div>').join("");
  s.innerHTML=rows+'<div class="stat"><span>Attack paths (\u2264 8 hops)</span><b>'+r.count+(r.capped?"+":"")+'</b></div><div class="stat"><span>Edges on an attack path</span><b>'+r.onPath.size+'</b></div>';
  document.getElementById("paths").innerHTML=D.nodes.filter(n=>n.target).map(t=>{const c=cheapest(t.id);
    if(!c)return '<div style="margin-bottom:8px"><b>'+t.id+'</b>: no path</div>';
    return '<div style="margin-bottom:8px"><b>'+t.id+'</b> (difficulty '+c.cost+')<br>'+c.path.map(e=>e.s+' \u2192 '+e.d+' <i>['+e.t+']</i>').join('<br>')+'</div>';}).join("");
  let cost=0;fixed.forEach(c=>{cost+=D.controls.find(x=>x.id==c).cost;});
  document.getElementById("cost").textContent="Total cost of ticked fixes: "+cost;
  D.controls.forEach(c=>{document.getElementById("cb_"+c.id).checked=fixed.has(c.id);});
}
const ctls=document.getElementById("ctls");
D.controls.forEach(c=>{const d=document.createElement("label");d.className="ctl";
  d.innerHTML='<input type="checkbox" id="cb_'+c.id+'"><span>'+c.name+'<br><span class="sub">'+c.id+'</span></span><span class="cost">cost '+c.cost+'</span>';
  d.querySelector("input").addEventListener("change",ev=>{ev.target.checked?fixed.add(c.id):fixed.delete(c.id);render();});
  ctls.appendChild(d);});
function setSet(a){fixed.clear();a.forEach(x=>fixed.add(x));render();}
document.getElementById("bOpt").onclick=()=>setSet(D.optimal);
document.getElementById("bGr").onclick=()=>setSet(D.greedy);
document.getElementById("bNone").onclick=()=>setSet([]);
const COLORS={user:"#60a5fa",group:"#a78bfa",workstation:"#34d399",svc:"#fbbf24",server:"#f472b6",crown:"#ef4444"};
document.getElementById("legend").innerHTML=Object.keys(COLORS).map(k=>'<span><i class="dot" style="background:'+COLORS[k]+'"></i>'+k+'</span>').join("")+'<span><i class="dot" style="border:2px solid #fff;box-sizing:border-box"></i>white ring = phishable entry / crown jewel</span>';
let vb={x:0,y:0,w:D.W,h:D.H};
function setVB(){svg.setAttribute("viewBox",vb.x+" "+vb.y+" "+vb.w+" "+vb.h);}
function zoom(f,cx,cy){cx=cx===undefined?vb.x+vb.w/2:cx;cy=cy===undefined?vb.y+vb.h/2:cy;
  const nw=Math.min(D.W,Math.max(D.W/8,vb.w*f)),k=nw/vb.w;vb={x:cx-(cx-vb.x)*k,y:cy-(cy-vb.y)*k,w:nw,h:vb.h*k};setVB();}
document.getElementById("zi").onclick=()=>zoom(.6);document.getElementById("zo").onclick=()=>zoom(1/.6);
document.getElementById("zr").onclick=()=>{vb={x:0,y:0,w:D.W,h:D.H};setVB();};
let drag=null;
svg.addEventListener("pointerdown",ev=>{drag={x:ev.clientX,y:ev.clientY,vx:vb.x,vy:vb.y};});
window.addEventListener("pointerup",()=>{drag=null;});
window.addEventListener("pointermove",ev=>{if(!drag)return;const r=svg.getBoundingClientRect();
  vb.x=drag.vx-(ev.clientX-drag.x)*vb.w/r.width;vb.y=drag.vy-(ev.clientY-drag.y)*vb.h/r.height;setVB();});
svg.addEventListener("wheel",ev=>{ev.preventDefault();const r=svg.getBoundingClientRect();
  zoom(ev.deltaY<0?.8:1.25,vb.x+(ev.clientX-r.left)*vb.w/r.width,vb.y+(ev.clientY-r.top)*vb.h/r.height);},{passive:false});
render();
if(location.hash=="#optimal")setSet(D.optimal);else if(location.hash=="#greedy")setSet(D.greedy);else if(location.hash=="#tiering")setSet(["TIERING"]);
window.__attackgraph={fixed,analyse,setSet,D};
</script></body></html>
""".replace("__W__", "1180").replace("__H__", "760")
