# Evaluation Plan — Zero Trust K8s

## Metrics Overview

| Metric | Definition |
|---|---|
| Detection latency | Time from misconfiguration introduced to ViolationEvent recorded |
| Remediation time | Time from ViolationEvent to confirmed API write |
| False positive rate | % of violations flagged that represent legitimate intentional config |
| Performance overhead | CPU/memory delta with controller running vs not running |
| Availability impact | Whether any auto-remediation causes pod restarts or dropped traffic |

---

## Metric 1: Detection Latency

**Definition:** Time elapsed from when a misconfiguration is applied to the cluster to when the system records a ViolationEvent.

**Measurement method:**
1. Write a test harness script that applies a known-bad manifest and records the apply timestamp (`T1`)
2. Parse the controller's structured JSON log stream for the corresponding ViolationEvent
3. Record the ViolationEvent timestamp as `T2`
4. Latency = `T2 - T1`

**Trial design:** Run 20 trials per violation type. Report mean, min, max, and p95.

**Expected results:**
- Timer-based detection: under 35 seconds (one reconcile interval)
- Event-based detection (watch trigger): under 5 seconds

---

## Metric 2: Remediation Time

**Definition:** Time from ViolationEvent emission to confirmed remediation applied (Kubernetes API confirms the write).

**Measurement method:** Internal to the controller. The audit log records both `ViolationEvent.detectedAt` and `RemediationAction.completedAt`. Remediation time = `completedAt - detectedAt`.

**Trial design:** Run 20 trials per auto-remediable violation type (NP-001, RBAC-001 low-risk). Report mean and p95.

---

## Metric 3: False Positive Rate

**Definition:** Percentage of ViolationEvents that are flagged as violations but represent intentional, legitimate configuration.

**Measurement method:**
1. Design 10 "legitimate exception" scenarios — roles and policies that look like violations but are correctly exempted via the CRD exemption list
2. Apply all 10 to the cluster with correct exemption annotations
3. Count how many still trigger ViolationEvents
4. False positive rate = `incorrectly flagged / 10`

**Ground truth:** You authored the test scenarios, so legitimate vs violation is known a priori.

**Target:** 0 false positives on exempted resources.

---

## Metric 4: Performance Overhead

**Definition:** Additional CPU and memory consumed by the cluster due to the running controller.

**Measurement method:**
1. Establish baseline: run cluster with no controller for 10 minutes, record CPU and memory of all system pods using `kubectl top pods -A`
2. Deploy controller, run for 30 minutes under normal reconcile load
3. Record CPU and memory again
4. Overhead = (controller-running values) - (baseline values)
5. Also measure Kubernetes API server request rate increase using Prometheus `apiserver_request_total`

**Tools:** `kubectl top`, Prometheus, minikube dashboard.

---

## Metric 5: Availability Impact

**Definition:** Whether auto-remediation actions interrupt running workload traffic or cause pod restarts.

**Measurement method:**
1. Deploy a simple HTTP server pod in a test namespace
2. Run a continuous curl loop against it logging response codes and timestamps
3. Apply a violation that triggers auto-remediation in that namespace (NP-001)
4. Monitor for: dropped HTTP requests, non-200 responses, pod restarts
5. Record any disruption window

**Expected result:** Zero dropped requests for NetworkPolicy additions — they are applied non-disruptively. Document any observed impact honestly.

---

## Test Scenario Catalog

| # | Scenario | Expected Violation | Expected Action |
|---|---|---|---|
| 1 | Apply ClusterRole with `verbs: ["*"]` | RBAC-001 HIGH | ESCALATE |
| 2 | Bind cluster-admin to test service account | RBAC-003 HIGH | ESCALATE |
| 3 | Create namespace with no NetworkPolicy | NP-001 LOW | AUTO: apply default-deny |
| 4 | Apply NetworkPolicy with empty podSelector | NP-002 | varies by context |
| 5 | Apply legitimate exempt role (FP test) | no violation | SKIP |
| 6 | Crash controller mid-cycle, observe recovery | none | clean restart, fresh cycle |
| 7 | Apply 10 violations simultaneously | multiple | rate limit fires, excess escalated |
| 8 | Enable dry-run mode, apply NP-001 violation | NP-001 | LOG only, no API write |
| 9 | Apply violation, verify rollback from audit log | RBAC-001 | manual restore test |
| 10 | Apply violation, remove it before next cycle | RBAC-001 | may not be detected (document gap) |

---

## Test Environment Setup

- **Cluster:** minikube single-node
- **Namespaces:** Create dedicated test namespaces (`test-low-risk`, `test-high-risk`, `test-exempt`) to isolate scenarios
- **Tooling:** Shell scripts in `evaluations/scenarios/` that apply and remove test manifests with timestamping
- **Log collection:** Pipe controller stdout to a file during evaluation runs for offline analysis
- **Metrics collection:** Prometheus scraping controller `/metrics` endpoint throughout all evaluation runs
