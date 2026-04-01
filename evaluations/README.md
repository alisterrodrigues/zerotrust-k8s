# Evaluation scenarios

Shell scripts under `scenarios/` support empirical measurement aligned with [docs/evaluation-plan.md](../docs/evaluation-plan.md).

## Prerequisites

- **Cluster:** minikube (or equivalent) is running and `kubectl` targets it.
- **Bootstrap:** Run `./setup.sh` from the repository root so namespaces, sample policies, and test fixtures (for example `test-exempt`) exist as expected.
- **Controller:** Start the manager locally with `make run` in a **separate** terminal so it uses your kubeconfig against the same cluster.
- **Metrics (scenario 03):** The controller must expose Prometheus metrics on `http://localhost:8080/metrics` (default for local `make run`).

Do not run multiple scenarios at once; they create cluster objects and can race on shared state or distort timing.

## What each scenario measures

| Script | What it measures |
|--------|------------------|
| `01-detect-np001.sh` | **Detection (and auto-remediation) latency** for NP-001: time from namespace creation until `ztk8s-default-deny-ingress` appears. |
| `02-detect-rbac001.sh` | **Detection latency** for RBAC-001 (HIGH risk): time until the violation is recorded in the `ztk8s-audit-log` ConfigMap (escalation path; no auto-fix). |
| `03-false-positive.sh` | **False positive rate** proxy: exempt / system namespaces should not appear as violations in metrics or receive unintended NP-001 remediation. |
| `04-rate-limit.sh` | **Safety / throttle behavior** when many NP-001-violating namespaces appear in one window: auto-remediations per cycle should not exceed the configured limit (script assumes limit `5`; align with your live `ZeroTrustPolicy`). |
| `05-availability.sh` | **Availability impact**: continuous HTTP checks while NP-001 remediation applies in the same namespace. |

```
// DEFENSE NOTE: Metric 1 (detection latency, NP-001 via 01) proves the reconciler observes cluster drift
// DEFENSE NOTE: within the evaluation SLO and that low-risk NP-001 is handled end-to-end without human action.

// DEFENSE NOTE: Metric 1 (RBAC-001 via 02) proves HIGH-risk findings are still detected and auditable
// DEFENSE NOTE: on the escalation path (audit ConfigMap), not silently ignored because we do not auto-fix them.

// DEFENSE NOTE: Metric 3 (false positives via 03) proves exemptions and namespace allowlists reduce alerting noise
// DEFENSE NOTE: and avoid unsafe auto-changes on intentional or protected configuration.

// DEFENSE NOTE: Rate limiting (04) proves the system caps blast radius under burst misconfiguration,
// DEFENSE NOTE: trading some deferred fixes for stability and operator review — a defensible Zero Trust control.

// DEFENSE NOTE: Metric 5 (availability via 05) proves NP-001 remediation (NetworkPolicy add) does not
// DEFENSE NOTE: observably drop in-namespace HTTP during the test window — supporting a claim of non-disruptive fixes.
```

**Performance overhead** (CPU/memory delta and API load with controller on vs off) is defined in the evaluation plan but is **not** automated in these scripts; use `kubectl top`, Prometheus, and the methodology in [docs/evaluation-plan.md](../docs/evaluation-plan.md) § Metric 4.

```
// DEFENSE NOTE: Overhead evidence shows the controller cost is bounded and acceptable on a capstone cluster,
// DEFENSE NOTE: and ties operational impact to the threat model (continuous audit vs resource use).

// DEFENSE NOTE: Remediation time (detectedAt → completedAt in the audit log) is defined for auto-fixable cases
// DEFENSE NOTE: in the plan; use audit log JSON and controller logs — scripts 01/05 observe wall-clock effect, not that delta.
```

## Mapping to [docs/evaluation-plan.md](../docs/evaluation-plan.md)

| Scenario script | Primary metric in evaluation plan | Notes |
|-----------------|-----------------------------------|--------|
| `01-detect-np001.sh` | **Metric 1: Detection latency** | Endpoint is appearance of remediated NetworkPolicy (detect + fix in one observation). |
| `02-detect-rbac001.sh` | **Metric 1: Detection latency** | Endpoint is audit log line for the test `ClusterRole` (HIGH → escalate, no auto-remediation). |
| `03-false-positive.sh` | **Metric 3: False positive rate** | Uses metrics + `kube-system` checks; extend with more exempt cases per plan. |
| `04-rate-limit.sh` | Plan **Test Scenario Catalog #7** (rate limit); complements **Metric 2** / safety | Keeps bulk NP-001 burst from unconstrained API writes. |
| `05-availability.sh` | **Metric 5: Availability impact** | Dropped/failed curls and optional pod restart checks. |
| *(manual / other tooling)* | **Metric 2: Remediation time** | Compare timestamps inside audit log entries. |
| *(manual / other tooling)* | **Metric 4: Performance overhead** | Baseline vs controller-on resource usage and `apiserver_request_total`. |

## How to run (one at a time)

From the repository root:

```bash
chmod +x evaluations/scenarios/*.sh   # once, after clone
./evaluations/scenarios/01-detect-np001.sh
# When finished and cluster is idle:
./evaluations/scenarios/02-detect-rbac001.sh
# ... and so on; do not parallelize on the same cluster for formal numbers.
```

Capture controller **stdout** (JSON logs) to a file during runs if you need ViolationEvent timestamps per the evaluation plan’s Metric 1 method.

## Recording results in `results.md`

Maintain a dated log in [results.md](results.md) (create the file on first run if it does not exist). For each script execution, append:

- Date/time (UTC), scenario id, cluster context name.
- Raw `RESULT:` lines printed by the script.
- Any PASS/FAIL or latency summary; for latency, plan says **20 trials** per violation type — repeat the script and record min/mean/max/p95 offline.
- Link or path to saved controller log slice for that trial.

This keeps empirical numbers traceable for the capstone write-up and defense.
