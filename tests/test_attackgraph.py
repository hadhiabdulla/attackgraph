"""Run: python tests/test_attackgraph.py   (needs only Python; the JS parity check also needs node)"""
import itertools, json, os, subprocess, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import attackgraph as ag
from report import write_html

g = ag.generate(7)

# 1. determinism
assert [(e["src"], e["dst"], e["type"]) for e in ag.generate(7).edges] == [(e["src"], e["dst"], e["type"]) for e in g.edges]

# 2. baseline: crown jewels exposed, shortest path is a real chain of existing edges
assert set(g.exposed_targets()) == set(g.targets())
for t in g.targets():
    cost, path = g.shortest_path(t)
    assert path[0]["src"] in g.entries() and path[-1]["dst"] == t
    assert all(a["dst"] == b["src"] for a, b in zip(path, path[1:]))
    assert cost == sum(ag.EDGE_TYPES[e["type"]][0] for e in path)

# 3. optimal set really cuts everything, and no cheaper set does (independent brute force)
cost, sub = g.optimal_cut()
assert g.exposed_targets(sub) == []
cids = sorted(g.controls)
cheaper = [s for k in range(len(cids) + 1) for s in itertools.combinations(cids, k)
           if g.cost(s) < cost and not g.exposed_targets(s)]
assert cheaper == [], cheaper

# 4. greedy cuts everything and is never cheaper than optimal
gc, gs = g.greedy_cut()
assert g.exposed_targets(gs) == [] and gc >= cost

# 5. removing a control never adds paths (monotone)
base = sum(g.count_paths(t)[0] for t in g.targets())
for c in cids:
    assert sum(g.count_paths(t, [c])[0] for t in g.targets()) <= base

# 6. edge-cut vs control-cut: unit min-cut is a lower bound on the number of edges any cut removes
removed_edges = sum(1 for e in g.edges if e["control"] in sub)
assert g.min_edge_cut() <= removed_edges

# 7. HTML works and its in-browser analysis agrees with Python
tmp = tempfile.mkdtemp()
html = os.path.join(tmp, "r.html")
write_html(g, ag.analyse(g), html)
text = open(html).read()
assert "http://" not in text.replace("http://www.w3.org/2000/svg", "") and "https://" not in text, "report makes/contains external URLs"
js = text.split("<script>")[1].split("</script>")[0]
harness = """
global.document={getElementById:()=>({setAttribute(){},appendChild(){},addEventListener(){},style:{},set innerHTML(v){},set textContent(v){},set onclick(v){},checked:false}),createElementNS:()=>({setAttribute(){},appendChild(){},addEventListener(){},removeAttribute(){}}),createElement:()=>({className:"",set innerHTML(v){},querySelector:()=>({addEventListener(){}}),addEventListener(){}})};
global.location={hash:""};global.window={addEventListener(){}};
""" + js + """
const cids=D.controls.map(c=>c.id);const out=[];
for(const set of JSON.parse(process.argv[2])){fixed.clear();set.forEach(x=>fixed.add(x));const r=analyse();out.push([r.count,r.exposed.length,r.onPath.size]);}
console.log(JSON.stringify(out));
"""
open(os.path.join(tmp, "h.js"), "w").write(harness)
sets = [[], ["TIERING"], ["ACL-1", "TIERING"], list(sub), list(gs), ["KERB", "LAPS", "RDP-MFA"]]
try:
    r = subprocess.run(["node", os.path.join(tmp, "h.js"), json.dumps(sets)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    js_out = json.loads(r.stdout)
    for s, (cnt, nexp, _) in zip(sets, js_out):
        py_cnt = sum(g.count_paths(t, s)[0] for t in g.targets())
        assert cnt == py_cnt and nexp == len(g.exposed_targets(s)), (s, cnt, py_cnt)
    print("JS/Python parity OK on", len(sets), "fix sets")
except FileNotFoundError:
    print("node not found: skipped JS parity check")
# 8. network size parameters + infeasible-cut handling
small = ag.generate(3, users=6, workstations=4, servers=2)
assert [(e["src"], e["dst"], e["type"]) for e in ag.generate(3, users=6, workstations=4, servers=2).edges] == \
       [(e["src"], e["dst"], e["type"]) for e in small.edges]
r_small = ag.analyse(small)
assert r_small["nodes"] == len(small.nodes)
# seed 2 gives an entry point a route no control removes: reported, never a crash
g2 = ag.generate(2)
r2 = ag.analyse(g2)
if g2.exposed_targets(sorted(g2.controls)):
    assert r2["optimal_cut"] is None and r2["uncuttable_targets"]
else:
    assert r2["optimal_cut"] is not None
# every edge endpoint is a real node at any size
for gg in (g, small, g2, ag.generate(11, users=40, workstations=24, servers=6)):
    assert all(e["src"] in gg.nodes and e["dst"] in gg.nodes for e in gg.edges)
print("size + infeasible-cut tests OK")

print("All AttackGraph tests passed")
