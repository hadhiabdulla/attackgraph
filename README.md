# AttackGraph

Exposure and fix-prioritisation on a synthetic enterprise network. It models privilege transitions (group memberships, local admin rights, cached credentials, shared passwords, weak service accounts), finds the attack paths from phishable users to crown-jewel assets, explains them in plain language, and works out which set of fixes closes the exposure at the lowest cost.

It is a **model**, not a scanner. It runs only on generated demo networks, never probes real systems, and says nothing about the security of any real organisation.

![All attack paths in red](docs/screenshot-exposed.png)

## Run it

```bash
git clone https://github.com/hadhiabdulla/attackgraph.git
cd attackgraph
python3 attackgraph.py                              # analysis in the terminal
python3 attackgraph.py --html docs/demo.html        # interactive report
python3 tests/test_attackgraph.py                   # tests
```

Python 3.8+, standard library only. Open `docs/demo.html` in a browser: tick fixes on the left and watch the red attack paths disappear. The side panel lists the cheapest attack path to each crown jewel in plain text (readable on a phone), and the graph can be zoomed (+ / - buttons, mouse wheel) and dragged. The page works offline and makes no network requests.

## The model

An edge `A -> B` means: *an attacker who controls A can gain control of B through this transition.*

| Edge | Meaning |
|---|---|
| MemberOf | A inherits B's rights |
| AdminTo | A is a local administrator on B |
| HasSession | a privileged login is cached on A, so B's credentials can be stolen from A |
| CanRDP | A may open remote desktop sessions to B (a foothold) |
| Kerberoast | B is a service account with a crackable password |
| PasswordReuse | A and B share a local admin password |
| WriteACL | A can edit B's permissions and add itself |

Every edge has a difficulty weight (used for cheapest-path search). Most edges are tied to a **control** that removes it. Some controls are broad (one policy removes many edges, e.g. unique local admin passwords), others fix one edge. Control costs are illustrative numbers in `generate()`; change them to see the ranking change.

## What it computes

* **Cheapest attack path** to each crown-jewel asset (Dijkstra), printed step by step with the reason for each hop.
* **Number of attack paths** (simple paths up to 8 hops).
* **Optimal control set:** the cheapest set of controls after which no crown jewel is reachable, found by exhaustive search over all control subsets (exact for this model, up to 18 controls).
* **Greedy control set:** repeatedly buy the control with the most paths removed per unit cost. Compared with the optimum, so you can see when the simple heuristic is wrong.
* **Best k controls** by paths removed (exact), for limited budgets.
* **Minimum edge cut** (max-flow): the fewest *individual edges* that would separate entries from targets. It differs from the control view because real fixes come as controls that remove many edges, and some cut the most paths without cutting every path. Both are shown on purpose.
* **Verification:** the reachability analysis is re-run after the fixes are applied, and the report repeats the check in the browser.

Sample output for the default network (`seed 7`):

```
Optimal control set: cost 10  -> ACL-1, ACL-2, TIERING
Greedy control set:  cost 11  -> JIT-ADMIN, KERB, RDP-MFA, ACL-1, ACL-2
Minimum number of individual edges to cut (graph min-cut): 3
Best 1 control by paths removed: TIERING (cost 8): paths 472 -> 2
```

Full text in [`docs/sample-output.txt`](docs/sample-output.txt).

| Fix set applied | Result |
|---|---|
| Privileged accounts never log on to workstations only | ![](docs/screenshot-tiering.png) |
| Optimal set | ![](docs/screenshot-optimal.png) |

## Tests

`tests/test_attackgraph.py` checks, among other things, that the optimal set really blocks every path and that an independent brute force finds nothing cheaper, that greedy is never cheaper than optimal, that removing a control never adds paths, and that the in-browser path counts match the Python results on several fix sets (needs `node` for that last check, skipped otherwise).

## Limits

* Synthetic networks only; the edge catalogue is a simplification of real privilege relationships.
* "Optimal" means optimal for this model's controls and illustrative costs, not a guarantee about any real environment.
* Path counts are capped at 8 hops and 200,000 paths.
* It models what is reachable, not how likely an attacker is to succeed.

## Files

`attackgraph.py` model, generator, analysis and command line. `report.py` builds the interactive HTML. `tests/` tests. `docs/` demo page and screenshots.
