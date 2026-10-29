"""
AttackGraph - exposure and fix-prioritisation on a synthetic enterprise network.

Model
  Nodes are principals and machines. A directed edge A -> B means: "an attacker
  who already controls A can gain control of B through this privilege
  transition". Edges come from a small, explicit catalogue (EDGE_TYPES). This is
  a MODEL for reasoning about exposure, not a scanner: it does not touch real
  systems, does not exploit anything, and says nothing about real networks.

Fixes (controls)
  Each control removes a set of edges. Some controls are broad (one policy
  covers many edges), some fix a single edge. Each control has a cost.

What it answers
  * Which entry points (phishable users) can reach each crown-jewel asset?
  * What are the cheapest attack paths, in plain language?
  * Which set of controls cuts every path, at the lowest total cost?
    (exact search over control sets) and how do cheaper heuristics compare?
  * How does that differ from the graph-theoretic minimum edge cut?
"""
import argparse, heapq, itertools, json, random, sys
from collections import defaultdict, deque

# type: (difficulty weight, explanation template)
EDGE_TYPES = {
    "MemberOf":      (1, "{a} is a member of {b}, so it inherits {b}'s rights"),
    "AdminTo":       (2, "{a} has local administrator rights on {b}"),
    "HasSession":    (3, "a privileged login from {b} is cached on {a}, so {b}'s credentials can be stolen from {a}"),
    "CanRDP":        (4, "{a} may open remote desktop sessions to {b}, giving a foothold there"),
    "Kerberoast":    (3, "{b} is a service account with a crackable password; any logged-in account such as {a} can request and crack its ticket"),
    "PasswordReuse": (2, "{a} and {b} share the same local administrator password"),
    "WriteACL":      (2, "{a} can edit the permissions of {b} and add itself to it"),
}


class Graph:
    def __init__(self):
        self.nodes = {}      # id -> {"type":..., "entry":bool, "target":bool}
        self.edges = []      # dicts: id, src, dst, type, control
        self.controls = {}   # id -> {"name", "cost", "desc"}

    def add_node(self, nid, ntype, entry=False, target=False):
        self.nodes[nid] = {"type": ntype, "entry": entry, "target": target}

    def add_edge(self, src, dst, etype, control):
        self.edges.append({"id": len(self.edges), "src": src, "dst": dst,
                           "type": etype, "control": control})

    def add_control(self, cid, name, cost, desc):
        self.controls[cid] = {"name": name, "cost": cost, "desc": desc}

    # ---------------------------------------------------------- queries
    def active(self, fixed=()):
        fixed = set(fixed)
        return [e for e in self.edges if e["control"] not in fixed]

    def entries(self):
        return [n for n, d in self.nodes.items() if d["entry"]]

    def targets(self):
        return [n for n, d in self.nodes.items() if d["target"]]

    def adjacency(self, fixed=()):
        adj = defaultdict(list)
        for e in self.active(fixed):
            adj[e["src"]].append(e)
        return adj

    def reachable(self, fixed=()):
        adj = self.adjacency(fixed)
        seen = set(self.entries())
        dq = deque(seen)
        while dq:
            u = dq.popleft()
            for e in adj[u]:
                if e["dst"] not in seen:
                    seen.add(e["dst"]); dq.append(e["dst"])
        return seen

    def exposed_targets(self, fixed=()):
        r = self.reachable(fixed)
        return [t for t in self.targets() if t in r]

    def shortest_path(self, target, fixed=()):
        """Dijkstra from all entry points; returns (cost, [edges]) or None."""
        adj = self.adjacency(fixed)
        dist = {n: 0 for n in self.entries()}
        prev = {}
        pq = [(0, n) for n in dist]
        heapq.heapify(pq)
        while pq:
            d, u = heapq.heappop(pq)
            if d > dist.get(u, 1e18):
                continue
            if u == target:
                break
            for e in adj[u]:
                nd = d + EDGE_TYPES[e["type"]][0]
                if nd < dist.get(e["dst"], 1e18):
                    dist[e["dst"]] = nd; prev[e["dst"]] = e
                    heapq.heappush(pq, (nd, e["dst"]))
        if target not in dist:
            return None
        path, n = [], target
        while n in prev:
            path.append(prev[n]); n = prev[n]["src"]
        return dist[target], path[::-1]

    def count_paths(self, target, fixed=(), max_hops=8, cap=200000):
        """Simple (no repeated node) entry->target paths up to max_hops edges.
        Returns (count, capped)."""
        adj = self.adjacency(fixed)
        # prune: only nodes that can reach the target matter
        radj = defaultdict(list)
        for e in self.active(fixed):
            radj[e["dst"]].append(e["src"])
        can = {target}; dq = deque([target])
        while dq:
            u = dq.popleft()
            for p in radj[u]:
                if p not in can:
                    can.add(p); dq.append(p)
        count = 0
        capped = False
        entries = [n for n in self.entries() if n in can]

        def dfs(u, seen, hops):
            nonlocal count, capped
            if capped:
                return
            if u == target:
                count += 1
                if count >= cap:
                    capped = True
                return
            if hops == max_hops:
                return
            for e in adj[u]:
                v = e["dst"]
                if v in can and v not in seen:
                    seen.add(v); dfs(v, seen, hops + 1); seen.discard(v)
        for s in entries:
            dfs(s, {s}, 0)
        return count, capped

    def describe(self, path):
        lines = []
        for e in path:
            tpl = EDGE_TYPES[e["type"]][1]
            lines.append(f"{e['src']} --{e['type']}--> {e['dst']}: " + tpl.format(a=e["src"], b=e["dst"]))
        return lines

    # ---------------------------------------------------------- remediation
    def cost(self, fixed):
        return sum(self.controls[c]["cost"] for c in fixed)

    def optimal_cut(self):
        """Exact: the cheapest set of controls after which no target is
        reachable. Exhaustive over control subsets (fine for <= ~18 controls)."""
        cids = sorted(self.controls)
        assert len(cids) <= 18, "too many controls for exhaustive search"
        best = None
        for k in range(len(cids) + 1):
            for sub in itertools.combinations(cids, k):
                c = self.cost(sub)
                if best is not None and c > best[0]:
                    continue
                if not self.exposed_targets(sub):
                    if best is None or c < best[0] or (c == best[0] and len(sub) < len(best[1])):
                        best = (c, sub)
        return best

    def greedy_cut(self):
        """Heuristic: repeatedly buy the control with the best
        (paths removed) / cost until nothing is exposed."""
        fixed = []
        remaining = set(self.controls)
        while self.exposed_targets(fixed):
            base = sum(self.count_paths(t, fixed)[0] for t in self.targets())
            best, score = None, -1
            for c in sorted(remaining):
                after = sum(self.count_paths(t, fixed + [c])[0] for t in self.targets())
                s = (base - after) / self.controls[c]["cost"]
                if s > score:
                    best, score = c, s
            if best is None or score <= 0:
                break
            fixed.append(best); remaining.discard(best)
        return self.cost(fixed), tuple(fixed)

    def best_k(self, k):
        """Exact: the k controls that remove the most attack paths."""
        base = sum(self.count_paths(t)[0] for t in self.targets())
        best = None
        for sub in itertools.combinations(sorted(self.controls), k):
            left = sum(self.count_paths(t, sub)[0] for t in self.targets())
            key = (left, self.cost(sub))
            if best is None or key < best[0]:
                best = (key, sub)
        return {"controls": best[1], "cost": self.cost(best[1]),
                "paths_before": base, "paths_after": best[0][0]}

    def min_edge_cut(self):
        """Graph-theoretic minimum number of single edges to delete so that no
        target is reachable (unit capacities, max-flow). Ignores that real fixes
        come as controls; a lower-bound style comparison."""
        S, T = "__S__", "__T__"
        cap = defaultdict(int)
        nb = defaultdict(set)

        def add(u, v, c):
            cap[(u, v)] += c; nb[u].add(v); nb[v].add(u)
        for e in self.edges:
            add(e["src"], e["dst"], 1)
        for n in self.entries():
            add(S, n, 10**6)
        for t in self.targets():
            add(t, T, 10**6)
        flow = 0
        while True:
            par = {S: None}; dq = deque([S])
            while dq and T not in par:
                u = dq.popleft()
                for v in nb[u]:
                    if v not in par and cap[(u, v)] > 0:
                        par[v] = u; dq.append(v)
            if T not in par:
                break
            v = T; b = 10**9
            while par[v] is not None:
                b = min(b, cap[(par[v], v)]); v = par[v]
            v = T
            while par[v] is not None:
                cap[(par[v], v)] -= b; cap[(v, par[v])] += b; v = par[v]
            flow += b
        return flow


# ------------------------------------------------------------------ generator
def generate(seed=7, users=24, workstations=16, servers=6):
    rnd = random.Random(seed)
    g = Graph()
    g.add_control("LAPS", "Unique local admin passwords (LAPS)", 5, "Randomise each machine's local administrator password")
    g.add_control("RDP-MFA", "MFA + allow-list for remote desktop", 3, "Require MFA and restrict who may use RDP")
    g.add_control("TIERING", "Privileged accounts never log on to workstations", 8, "Admin tiering / protected logon policy")
    g.add_control("KERB", "Long random service-account passwords (gMSA)", 2, "Remove crackable Kerberos service tickets")
    g.add_control("JIT-ADMIN", "Remove standing local admin from groups", 4, "Just-in-time admin instead of permanent group rights")

    gnames = ["Helpdesk", "IT-Ops", "Backup-Operators", "DB-Admins", "Contractors", "Domain-Admins"]
    for n in gnames:
        g.add_node(n, "group")
    ws = [f"WS-{i:02d}" for i in range(1, workstations + 1)]
    sv = ["FILE-01", "FILE-02", "APP-01", "APP-02", "BACKUP-01", "SQL-01"][:servers]
    svc = ["svc-backup", "svc-sql", "svc-web"]
    usr = [f"user{i:02d}" for i in range(1, users + 1)]
    for n in ws: g.add_node(n, "workstation")
    for n in sv: g.add_node(n, "server")
    for n in svc: g.add_node(n, "svc")
    phish = set(rnd.sample(usr, max(3, users // 6)))
    for n in usr: g.add_node(n, "user", entry=(n in phish))
    g.add_node("DC-01", "crown", target=True)
    g.add_node("FINANCE-DB", "crown", target=True)

    # group memberships
    for u in usr:
        r = rnd.random()
        if r < 0.12: g.add_edge(u, "Helpdesk", "MemberOf", None)
        elif r < 0.18: g.add_edge(u, "Contractors", "MemberOf", None)
        elif r < 0.22: g.add_edge(u, "IT-Ops", "MemberOf", None)
    admins = rnd.sample(usr, 2)
    for u in admins: g.add_edge(u, "Domain-Admins", "MemberOf", None)
    g.add_edge("Domain-Admins", "DC-01", "AdminTo", None)
    g.add_edge("Domain-Admins", "FINANCE-DB", "AdminTo", None)
    g.add_edge("DB-Admins", "FINANCE-DB", "AdminTo", None)
    g.add_edge("IT-Ops", "Backup-Operators", "MemberOf", "NEST-1"); g.add_control("NEST-1", "Remove IT-Ops from Backup-Operators", 1, "Single nested-group membership")
    g.add_edge("Backup-Operators", "DC-01", "AdminTo", "BKP-DC"); g.add_control("BKP-DC", "Remove Backup-Operators rights on DC-01", 2, "Single edge: backup rights on the domain controller")
    g.add_edge("Contractors", "DB-Admins", "WriteACL", "ACL-1"); g.add_control("ACL-1", "Fix Contractors write access on DB-Admins", 1, "Single permissions fix")
    g.add_edge("Helpdesk", "IT-Ops", "WriteACL", "ACL-2"); g.add_control("ACL-2", "Fix Helpdesk write access on IT-Ops", 1, "Single permissions fix")
    # standing local admin
    for w in ws: g.add_edge("Helpdesk", w, "AdminTo", "JIT-ADMIN")
    for s in sv[:4]: g.add_edge("IT-Ops", s, "AdminTo", "JIT-ADMIN")
    # RDP
    for u in rnd.sample(usr, 8):
        g.add_edge(u, rnd.choice(ws), "CanRDP", "RDP-MFA")
    for s in sv:
        g.add_edge("Contractors", s, "CanRDP", "RDP-MFA")
    # cached privileged sessions on workstations/servers (host -> principal)
    for w in rnd.sample(ws, 5):
        g.add_edge(w, rnd.choice(admins), "HasSession", "TIERING")
    g.add_edge(rnd.choice(ws), "IT-Ops", "HasSession", "TIERING")
    g.add_edge("BACKUP-01", "Backup-Operators", "HasSession", "TIERING")
    g.add_edge("SQL-01", "DB-Admins", "HasSession", "TIERING")
    # service accounts
    for u in usr[:6]:
        pass
    for s in svc:
        for u in rnd.sample(usr, 3):
            g.add_edge(u, s, "Kerberoast", "KERB")
    g.add_edge("svc-backup", "BACKUP-01", "AdminTo", None)
    g.add_edge("svc-sql", "SQL-01", "AdminTo", None)
    g.add_edge("svc-web", "APP-01", "AdminTo", None)
    g.add_edge("svc-backup", "Backup-Operators", "MemberOf", "SVC-BKP"); g.add_control("SVC-BKP", "Remove svc-backup from Backup-Operators", 1, "Single membership fix")
    # shared local admin passwords
    for a, b in itertools.combinations(ws[:6], 2):
        g.add_edge(a, b, "PasswordReuse", "LAPS"); g.add_edge(b, a, "PasswordReuse", "LAPS")
    for a, b in [("APP-01", "APP-02"), ("APP-02", "APP-01"), ("FILE-01", "FILE-02"), ("FILE-02", "FILE-01"),
                 ("APP-01", ws[0]), (ws[0], "APP-01"), ("SQL-01", "APP-02"), ("APP-02", "SQL-01")]:
        g.add_edge(a, b, "PasswordReuse", "LAPS")
    # a compromised server hands over the crown-jewel database
    g.add_edge("SQL-01", "FINANCE-DB", "HasSession", "TIERING")
    return g


def analyse(g):
    out = {"nodes": len(g.nodes), "edges": len(g.edges), "controls": len(g.controls),
           "entries": g.entries(), "targets": {}}
    for t in g.targets():
        sp = g.shortest_path(t)
        n, capped = g.count_paths(t)
        out["targets"][t] = {
            "exposed": sp is not None,
            "shortest_cost": sp[0] if sp else None,
            "shortest_path": g.describe(sp[1]) if sp else [],
            "paths_up_to_8_hops": n, "count_capped": capped}
    opt = g.optimal_cut()
    gr = g.greedy_cut()
    out["optimal_cut"] = {"controls": list(opt[1]), "cost": opt[0]}
    out["greedy_cut"] = {"controls": list(gr[1]), "cost": gr[0]}
    out["min_single_edge_cut"] = g.min_edge_cut()
    out["best_k"] = {str(k): g.best_k(k) for k in (1, 2, 3)}
    out["verify"] = {"exposed_after_optimal": g.exposed_targets(opt[1]),
                     "exposed_after_greedy": g.exposed_targets(gr[1])}
    return out


def main():
    ap = argparse.ArgumentParser(description="AttackGraph: exposure and fix prioritisation on a synthetic network")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--users", type=int, default=24)
    ap.add_argument("--json", help="write full analysis JSON here")
    ap.add_argument("--html", help="write the interactive report here")
    a = ap.parse_args()
    g = generate(a.seed, a.users)
    res = analyse(g)
    print(f"Synthetic network (seed {a.seed}): {res['nodes']} nodes, {res['edges']} edges, "
          f"{res['controls']} controls, {len(res['entries'])} phishable entry points\n")
    for t, d in res["targets"].items():
        print(f"== {t}: {'EXPOSED' if d['exposed'] else 'not reachable'}")
        if d["exposed"]:
            print(f"   cheapest path (difficulty {d['shortest_cost']}):")
            for l in d["shortest_path"]:
                print("    -", l)
            print(f"   attack paths up to 8 hops: {d['paths_up_to_8_hops']}{'+' if d['count_capped'] else ''}")
    c = g.controls
    def show(name, r):
        print(f"{name}: cost {r['cost']}")
        for x in r["controls"]:
            print(f"    - {x} ({c[x]['cost']}): {c[x]['name']}")
    print()
    show("Optimal control set (exact search, all targets unreachable)", res["optimal_cut"])
    show("Greedy control set (best paths-removed per cost)", res["greedy_cut"])
    print(f"Minimum number of individual edges to cut (graph min-cut): {res['min_single_edge_cut']}")
    print("  (real fixes come as controls that remove many edges at once, so this is only a comparison)\n")
    for k, r in res["best_k"].items():
        print(f"Best {k} control(s) by paths removed: {', '.join(r['controls'])} "
              f"(cost {r['cost']}): paths {r['paths_before']} -> {r['paths_after']}")
    print("\nVerification (recomputed after applying fixes): exposed targets after optimal =",
          res["verify"]["exposed_after_optimal"] or "none", "| after greedy =",
          res["verify"]["exposed_after_greedy"] or "none")
    if a.json:
        json.dump(res, open(a.json, "w"), indent=1)
    if a.html:
        from report import write_html
        write_html(g, res, a.html)
        print("wrote", a.html)


if __name__ == "__main__":
    main()
