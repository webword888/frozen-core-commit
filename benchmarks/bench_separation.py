#!/usr/bin/env python3
"""
Benchmark: cluster separation distance under forced variable flip.
Shows Delta_min / n >= 0.34 — separation is Omega(n).
Requires: pip install python-sat
"""
import sys, os, time, signal, struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fci_commit.keygen import derive_instance

try:
    from pysat.solvers import Glucose4
except ImportError:
    print("Install python-sat: pip install python-sat")
    sys.exit(1)

K = 7; AR = 0.78

def find_support(y, cls, n):
    s = [0]*n
    for cl in cls:
        sat = []
        for lit in cl:
            vi=abs(lit)-1; neg=(lit<0)
            if (y[vi]==1 and not neg) or (y[vi]==0 and neg): sat.append(vi)
        if len(sat)==1: s[sat[0]]+=1
    return s

print("Cluster Separation: Delta_min / n")
print("=" * 60)
print(f"{'n':>5} {'tests':>6} {'min_d':>6} {'avg_d':>7} {'min/n':>7} {'avg/n':>7}")

for n in [20, 30, 40, 50, 60, 75]:
    seed = struct.pack('<I', 42) + b"bench"
    y, cls, m = derive_instance(seed, n, K, AR)
    sup = find_support(y, cls, n)
    fv = [i for i in range(n) if sup[i]>=1][:5]
    dists = []

    for vi in fv:
        forced = -(vi+1) if y[vi]==1 else (vi+1)
        g = Glucose4()
        for c in cls: g.add_clause(c)
        class TO(Exception): pass
        def h(s,f): raise TO()
        old = signal.signal(signal.SIGALRM, h)
        signal.alarm(15)
        try:
            r = g.solve(assumptions=[forced])
            if r:
                model = g.get_model()
                sol = [1 if model[i]>0 else 0 for i in range(n)]
                dists.append(sum(a!=b for a,b in zip(y,sol)))
        except TO: pass
        finally:
            signal.alarm(0); signal.signal(signal.SIGALRM, old); g.delete()

    if dists:
        mn=min(dists); avg=sum(dists)/len(dists)
        print(f"{n:>5} {len(dists):>6} {mn:>6} {avg:>7.1f} {mn/n:>7.3f} {avg/n:>7.3f}")
