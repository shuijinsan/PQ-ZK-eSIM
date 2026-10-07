# Changelog

## Revision for the artifact-evaluation response (2026-10)

### Changes that affect evaluation results or how they are judged

- **`validate.py` (behavior).** The validator previously accepted invalid data.
  Timings that are non-numeric, `NaN`, `+/-inf`, zero or negative now fail;
  ratio columns must lie in `[0, 1]`; the `Speedup` row is recomputed from the
  two timing rows and compared with the value written in the file instead of
  being trusted. Checked against the three cases reported by the reviewer
  (Claim 1 timings set to `-1`; Claim 3 `Speedup` set to a non-numeric string;
  Claim 5 rates set to `NaN`) — all three are now rejected, while the recorded
  reference data still passes.
- **Claim 5 output collection (behavior).** `claims/claim5_sparse_noise/run.sh`
  now also collects `sparse_noise_norm_breakdown.csv` into `results/`, and the
  validator checks it. `detection_rate` in the main CSV is the union of the
  four checks (ell_2 lower bound, ell_2 upper bound, ell_infinity, ell_1 lower
  bound); Figure 7A plots the ell_1 lower-bound rate specifically, which is
  `l1_low_rate` in the breakdown file. Both the claim text and the README now
  say so.
- **Claim 5 claim text.** `rho` was described as the fraction of zeroed
  coefficients; it is the fraction *retained*. Corrected in the claim text to
  match the code and the README.
- **Claim 2 setup (behavior).** `setup.sh` is self-contained and
  non-interactive: it reuses an existing SageMath when one is usable and
  otherwise bootstraps conda and installs SageMath from conda-forge only
  (`--override-channels`), so it never reaches the defaults-channel
  terms-of-service prompt. `sage_major()` also puts SageMath's own bin
  directory on `PATH` — without it a conda-forge SageMath cannot load Singular,
  and a usable installation was misreported as unusable. `run.sh` reads the
  interpreter path recorded by `setup.sh`, so no `conda activate` or manual
  `PATH` edit is required.
- **`install.sh` (behavior).** `numpy`, `pandas` and `matplotlib` are installed
  as distribution packages in the same apt transaction as the other system
  dependencies, instead of `pip install --user`, which the externally managed
  system Python on Ubuntu 22.04/24.04 does not support. `curl` is installed
  with them.

### Documentation

- README: new "Start here" block (install prerequisites, sudo and network use,
  license locations, measured tool versions, badge evidence) and a runtime
  budget table; one accurate quick/full command sequence; Claim 2 prerequisites
  and its `setup.sh` → `run.sh` → `validate.sh --full` order.
- README / Claim 3: `AuthToken-enforced freshness after a successful local
  match` replaces the earlier `liveness` wording. No liveness or presentation
  attack detection is claimed.
- `infrastructure/access.txt` and the `install.sh` closing message: the
  misleading `run.sh [--quick|--full]` hint was removed — those scripts do not
  parse arguments and `--quick`/`--full` belong to `validate.sh`. The clone
  command now carries the real URL and a `cd`.
- `infrastructure/THIRD_PARTY.md`: the license file name was corrected to
  `license.txt`.

### Repository hygiene

- Removed the checked-in `.cxx/` CMake cache from the vendored OpenCV tree, an
  empty `artifact/demo/DEMO_GUIDE.md`, a placeholder `.gitkeep`, the stale
  `LEGACY_BASELINE_NOTICE.txt` files and the historical `estimator_stdout.txt`.
- `.gitignore` now covers the demo and claim run artifacts (`.demo_work/`,
  `claims/*/results/`), and the claim scripts delete their temporary CSVs from
  the repository root after copying them into `results/`.

### Figures

- The plotting scripts emit PNG, PDF and SVG. The PDF fonts are embedded as
  TrueType (`fonttype 42`) rather than Type 3, which IEEE/ACM typesetting
  rejects.
