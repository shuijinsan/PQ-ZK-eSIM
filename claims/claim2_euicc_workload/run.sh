#!/bin/bash
# Claim 2: Figure 6 Callgrind profile (B-class: requires Valgrind >= 3.20).
# Profiles a SINGLE authentication session (PERF_REPEAT=1) on the Release
# (-O2) build, native x86 (Valgrind cannot run under QEMU ARM64).
# Usage: bash claims/claim2/run.sh [--quick|--full]   (both equivalent)
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
command -v valgrind >/dev/null || { echo "valgrind not found; install valgrind (>= 3.20)."; exit 1; }

SRC=artifact/terminal/euicc/benchmarks/bench_pqzkesim.c
cp "$SRC" /tmp/bench_pqzkesim.c.bak
trap 'cp /tmp/bench_pqzkesim.c.bak "$SRC"' EXIT
# Single session.
sed -i 's/#define PERF_REPEAT 1000/#define PERF_REPEAT 1/' "$SRC"

# Release (-O2) build.
cmake -S artifact/terminal/euicc -B artifact/terminal/euicc/build -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build artifact/terminal/euicc/build --target bench_pqzkesim -j"$(nproc)" >/dev/null

CG_OUT=/tmp/pqzk_callgrind.out
valgrind --tool=callgrind --callgrind-out-file="$CG_OUT" artifact/terminal/euicc/build/bench_pqzkesim --perf

# Parse callgrind.out for exclusive per-function Ir, keep project functions.
python3 - "$CG_OUT" <<'PYEOF' > callgrind_top_functions.csv
import sys, re
funcs, cost = {}, {}
cur_fn, in_edge = None, False
for line in open(sys.argv[1], errors="replace"):
    line = line.rstrip("\n")
    if line.startswith("fn="):
        m = re.match(r"fn=\((\d+)\)\s+(.*)", line)
        if m:
            cur_fn = int(m.group(1)); funcs[cur_fn] = m.group(2).strip(); in_edge = False
    elif line.startswith("cfn=") or line.startswith("calls="):
        in_edge = True
    elif re.match(r"^[\d*+]", line) and not in_edge and cur_fn is not None:
        p = line.split()
        if len(p) >= 2:
            try: cost[cur_fn] = cost.get(cur_fn, 0) + int(p[1])
            except ValueError: pass
items = sorted(cost.items(), key=lambda kv: -kv[1])
LIB = ("EVP_","OPENSSL_","CRYPTO_","OSSL_","BIO_","BN_","HMAC_","OBJ_","ENGINE","NCONF",
       "_IO_","_int_","_dl_","_itoa","alloc_","__","0x","mem","str","rand","RAND","free",
       "malloc","calloc","realloc","pthread","read","write","posix_","check_","close","open",
       "lseek","madvise","mmap","munmap","syscall","clock_","gettime")
def project(name):
    return not name.startswith(LIB)
# strip GCC clone suffixes (.part.0 / .isra.0 / .constprop.0)
def clean(name):
    return re.sub(r"\.(part|isra|constprop)(\.[0-9]+)?$", "", name)
rows = [(clean(funcs[f]), c) for f, c in items if project(funcs.get(f, ""))]
print("function,instructions")
for name, c in rows[:10]:
    print(f"{name},{c}")
PYEOF

mkdir -p claims/claim2_euicc_workload/results
cp callgrind_top_functions.csv claims/claim2_euicc_workload/results/
echo "Done. See claims/claim2_euicc_workload/results/callgrind_top_functions.csv"
