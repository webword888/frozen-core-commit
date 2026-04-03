#!/usr/bin/env python3
"""
Benchmark: concrete classical cryptanalysis.
Measures CDCL solver scaling on planted k-SAT at operating parameters.
Requires: pip install python-sat
"""
import sys, os, time, math, signal, struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fci_commit.keygen import derive_instance

try:
    from pysat.solvers import Glucose4, Minisat22
except ImportError:
    print("Install python-sat: pip install python-sat")
    sys.exit(1)

K = 7; AR = 0.78; SEEDS = 5; TIMEOUT = 30

print("Concrete Cryptanalysis: Planted k-SAT at k=7, alpha/alpha_s=0.78")
print("=" * 70)
print(f"{'n':>5} {'m':>7} {'Glucose':>12} {'conflicts':>12} {'MiniSat':>12} {'conflicts':>12}")

data = []
for n in [30, 40, 50, 60, 75, 100]:
    gt = []; gc = []; mt = []; mc = []
    skip_g = skip_m = False
    for si in range(SEEDS):
        seed = struct.pack('<I', si + 1000*n) + b"bench"
        _, cls, m = derive_instance(seed, n, K, AR)

        for SolverCls, times, confs, skip_flag in [
            (Glucose4, gt, gc, skip_g), (Minisat22, mt, mc, skip_m)
        ]:
            if skip_flag: continue
            s = SolverCls()
            for c in cls: s.add_clause(c)
            class TO(Exception): pass
            def h(sig,fr): raise TO()
            old = signal.signal(signal.SIGALRM, h)
            signal.alarm(TIMEOUT)
            try:
                r = s.solve()
                el = time.perf_counter()
                st = s.accum_stats()
                times.append(el)
                confs.append(st.get('conflicts', 0))
            except TO:
                times.append(TIMEOUT)
            finally:
                signal.alarm(0); signal.signal(signal.SIGALRM, old); s.delete()

    avg_gt = sum(gt)/len(gt) if gt else TIMEOUT
    avg_gc = sum(gc)/len(gc) if gc else 0
    avg_mt = sum(mt)/len(mt) if mt else TIMEOUT
    avg_mc = sum(mc)/len(mc) if mc else 0

    print(f"{n:>5} {int(AR*(2**K)*0.693147*n):>7} {avg_gt:>10.3f}s {avg_gc:>12.0f} {avg_mt:>10.3f}s {avg_mc:>12.0f}")
    if avg_gt < TIMEOUT:
        data.append((n, avg_gt))

if len(data) >= 3:
    xs = [d[0] for d in data]
    ys = [math.log2(d[1]) for d in data]
    N = len(xs)
    sx=sum(xs);sy=sum(ys);sxy=sum(x*y for x,y in zip(xs,ys));sx2=sum(x*x for x in xs)
    b=(N*sxy-sx*sy)/(N*sx2-sx**2);a=(sy-b*sx)/N
    print(f"\nFit: log2(time) = {a:.2f} + {b:.4f}*n")
    print(f"Growth rate: 2^({b:.4f}*n)")
    for tn in [547, 820, 1094]:
        print(f"  n={tn}: ~2^{a+b*tn:.0f} seconds = ~2^{a+b*tn+30:.0f} ops")
