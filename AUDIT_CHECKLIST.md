# Zero Trust K8s — Living Audit Checklist

This file is the authoritative record of every known bug, gap, unimplemented
spec item, and open question in the codebase. It is maintained by the Claude.ai
project ("Zero trust architecture for Kubernetes capstone") and updated after
every fix session.

**Rules:**
- Before writing any Cursor/Claude Code prompt, check this file first
- After every fix is confirmed in the repo, mark the item ✅ FIXED with date
- Never delete items — only change their status
- Items without a status are open

---

## CRITICAL — Must Fix Before Production

### C-1 — `RequireApprovalFor` field is silently ignored
**File:** `internal/controller/decision.go`, `api/v1alpha1/zerotrustpolicy_types.go`  
**Status:** 🔴 OPEN  
**Description:** The CRD exposes `spec.remediation.requireApprovalFor: ["ClusterAdminBinding"]` as
a documented security control. The sample CR sets it. But `Decide()` in `decision.go` never reads
this field. Any violation type listed there is NOT forced to escalate — it goes through the normal
matrix. An operator setting this field believes they have a safety guarantee they don't have.  
**Fix:** In `Decide()`, after reading the mode, check if `event.ViolationType` matches any entry
in `policy.Remediation.RequireApprovalFor`. If so, return `DecisionActionEscalate` immediately
before consulting the matrix.

### C-2 — NP-001 detection logic is wrong for production
**File:** `internal/controller/detection.go`, `detectNamespacesWithoutNetworkPolicy`  
**Status:** 🔴 OPEN  
**Description:** NP-001 flags a namespace if `len(npList.Items) == 0` — i.e., no NetworkPolicy
at all. A namespace with a single wide-open `allow-all` NetworkPolicy passes NP-001 with no
violation. This is fundamentally incorrect for Zero Trust: the check should verify that a
default-deny ingress policy specifically exists, not just that any NetworkPolicy exists.  
**Fix:** Change the check to look for a NetworkPolicy where `spec.podSelector` is empty (`{}`)
AND `spec.policyTypes` contains `Ingress` AND `spec.ingress` is empty (`[]`). If no such policy
exists, flag NP-001.

### C-3 — `applyRemediation` in `remediation.go` still calls `AppendAuditEntry` individually
**File:** `internal/controller/remediation.go`  
**Status:** 🔴 OPEN  
**Description:** The NP-001 and RBAC-001 autofix paths each call `AppendAuditEntry` (singular)
after their write. The main reconcile loop uses `AppendAuditEntries` (batch). These two paths
can race on ConfigMap `resourceVersion` during startup when multiple autofixes fire in the same
burst cycle. The startup conflict errors seen in sessions are caused by this.  
**Fix:** Change `applyDefaultDenyIngressForNP001` and `removeWildcardVerbsForRBAC001Low` to
return an `AuditEntry` value to the caller instead of writing it themselves. The caller
(`applyRemediation`) returns it. The main loop appends it to `pendingAuditEntries` and writes
it in the single batch call after the loop.

### C-4 — RBAC-003 only checks `ClusterRoleBinding`, not namespaced `RoleBinding` to cluster-admin
**File:** `internal/controller/detection.go`, `detectClusterAdminBindings`  
**Status:** 🔴 OPEN  
**Description:** `detectClusterAdminBindings` only lists `ClusterRoleBindingList`. A namespaced
`RoleBinding` that references `cluster-admin` as its roleRef (which is valid Kubernetes, though
unusual) is completely invisible to this detector. This is a real detection gap.  
**Fix:** After the ClusterRoleBinding loop, iterate all namespaces and list `RoleBindingList`
per namespace, checking `roleRef.name == "cluster-admin"` using the same exclusion logic.

---

## HIGH — Fix Soon, Before New Feature Work

### H-1 — Controller has no watches on audited resource types
**File:** `internal/controller/zerotrustpolicy_controller.go`, `SetupWithManager`  
**Status:** 🔴 OPEN  
**Description:** `SetupWithManager` only calls `.For(&ZeroTrustPolicy{})`. The controller
never sets up watches on `ClusterRole`, `ClusterRoleBinding`, `NetworkPolicy`, or `Namespace`
objects. This means a misconfiguration introduced between two 30-second cycles can exist
for up to 30 seconds before detection. In production a watch would trigger immediate reconcile.  
**Fix:** Add `.Watches()` calls in `SetupWithManager` for ClusterRole, ClusterRoleBinding,
NetworkPolicy, and Namespace with an `EnqueueRequestsFromMapFunc` that always returns the
cluster-baseline key.

### H-2 — `RecordEscalation` called before audit write succeeds
**File:** `internal/controller/zerotrustpolicy_controller.go`  
**Status:** 🔴 OPEN  
**Description:** In the ESCALATE and default cases, `RecordEscalation()` is called inside the
for loop immediately after appending to `pendingAuditEntries`. But `AppendAuditEntries` doesn't
run until after the loop. If the audit write fails and the reconciler returns an error, the
Prometheus escalation counter has already been incremented but the audit entry was never
persisted. On retry the counter increments again for the same event.  
**Fix:** Move all `RecordEscalation` calls to after `AppendAuditEntries` succeeds.

### H-3 — `RateLimit` CRD comment says "per minute", enforcement is per cycle (30s)
**File:** `api/v1alpha1/zerotrustpolicy_types.go`  
**Status:** 🔴 OPEN  
**Description:** The CRD field comment reads "maximum number of remediations applied per minute".
The actual enforcement in `remediationRateLimit()` resets the counter each reconcile cycle
(every 30 seconds). The comment is wrong by 2x.  
**Fix:** Update the field comment to "per reconcile cycle (default 30s interval)".

### H-4 — `buildAuditEntryID` uses second-granularity timestamps causing duplicate IDs
**File:** `internal/controller/zerotrustpolicy_controller.go`  
**Status:** 🟡 WARN  
**Description:** `buildAuditEntryID` formats time as `20060102150405` (second precision).
Multiple violations of the same type against the same resource in the same second produce
identical EntryIDs. In steady state this doesn't matter, but under burst conditions or in
tests it can cause log confusion.  
**Fix:** Use nanosecond precision: `time.Now().UTC().Format("20060102150405.000000000")` or
append a short random suffix using `fmt.Sprintf("%s-%04d", ..., rand.Intn(10000))`.

### H-5 — `json.Marshal(ns)` result discarded in `applyDefaultDenyIngressForNP001`
**File:** `internal/controller/remediation.go`  
**Status:** 🟡 WARN  
**Description:** `applyDefaultDenyIngressForNP001` calls `json.Marshal(ns)` and discards
the result. This is dead code — the snapshot is already captured in `event.ResourceSnapshot`
by the detector. The marshal call adds latency with no benefit.  
**Fix:** Remove the `json.Marshal(ns)` call entirely.

---

## MEDIUM — Detection Breadth (Unimplemented Spec Items)

These are documented in `docs/remediation-model.md` and the task schedule but have zero
implementation. They make the docs run ahead of the code.

### M-1 — RBAC-004 not implemented (namespaced Role wildcard verbs)
**File:** `internal/controller/detection.go`  
**Status:** 🔴 OPEN  
**Description:** The remediation model documents RBAC-004 as wildcard verb detection on
namespaced `Role` objects (not ClusterRoles). Currently only ClusterRoles are scanned.  

### M-2 — RBAC-005 not implemented (namespaced Role wildcard resources)
**File:** `internal/controller/detection.go`  
**Status:** 🔴 OPEN  
**Description:** Same as RBAC-004 but for wildcard resources on namespaced Roles.

### M-3 — NP-002 not implemented (missing default-deny egress)
**File:** `internal/controller/detection.go`  
**Status:** 🔴 OPEN  
**Description:** `spec.networkPolicy.requireDefaultDenyEgress` is a CRD field that is read
but never acted upon. No egress NetworkPolicy detector exists.

### M-4 — `DenyWildcardVerbs` flag silently controls RBAC-002 detection
**File:** `internal/controller/detection.go`, `internal/controller/zerotrustpolicy_controller.go`  
**Status:** 🟡 WARN (documentation/naming issue)  
**Description:** `clusterRoleWildcardFlags` returns both `hasWildcardVerb` and
`hasWildcardResource`. Both are checked under the single `DenyWildcardVerbs` CRD flag.
There is no separate `DenyWildcardResources` field, meaning RBAC-002 detection cannot be
independently toggled. This is a CRD design inconsistency vs the documented behaviour.

---

## LOW — Polish and Test Coverage

### L-1 — envtest binaries not set up, `go test` fails
**File:** `Makefile` target `setup-envtest`  
**Status:** 🔴 OPEN  
**Description:** Running `go test ./internal/controller/... -v` fails with
"no such file or directory" for etcd binaries. `make setup-envtest` has never been run
on the development machine.  
**Fix (one-time):** Run `make setup-envtest` in the repo root. Tests will pass afterward.

### L-2 — Controller integration test only asserts RequeueAfter, no violation detection
**File:** `internal/controller/zerotrustpolicy_controller_test.go`  
**Status:** 🟡 WARN  
**Description:** The only test assertion is `res.RequeueAfter == 30s`. No test creates
a violating ClusterRole or namespace and verifies a violation is detected. Test coverage
of the actual detection logic is zero.  
**Fix:** Add two `It()` blocks: one that creates a ClusterRole with `verbs: ["*"]` and
asserts RBAC-001 appears in the returned events; one that creates a namespace with no
NetworkPolicy and asserts NP-001 appears.

### L-3 — `ZeroTrustPolicyStatus` conditions never written
**File:** `internal/controller/zerotrustpolicy_controller.go`  
**Status:** 🟡 WARN  
**Description:** The CRD has `status.conditions` defined with full Kubebuilder markers.
The reconciler never calls `r.Status().Update()`. `kubectl get zerotrustpolicy` shows
no status. Makes the system invisible to standard Kubernetes operators.  
**Fix:** After the reconcile cycle summary log, write a `metav1.Condition` of type
`AuditComplete` with a message summarising the cycle (violations found, auto-fixed, escalated).

### L-4 — `RequireNamespacedRoles` field is defined but never enforced
**File:** `api/v1alpha1/zerotrustpolicy_types.go`, `internal/controller/detection.go`  
**Status:** 🟡 WARN  
**Description:** `spec.rbac.requireNamespacedRoles: true` is in the CRD and sample CR.
No detector checks whether cluster-scoped ClusterRoles are being used where namespaced
Roles would suffice.  

---

## FIXED

*(Items move here once confirmed in the repo with date)*

- ✅ FIXED 2026-04-01 — ConfigMap optimistic concurrency conflict: main loop now batches all
  audit entries into single `AppendAuditEntries` call after the for loop
- ✅ FIXED 2026-04-01 — `02-detect-rbac001.sh` timeout: extended to 90s, searches all
  ConfigMap data keys via python3 JSON parsing
- ✅ FIXED 2026-04-02 — `setup.sh` now auto-deletes audit log ConfigMap on startup to
  prevent 1MB overflow across sessions
- ✅ FIXED 2026-04-02 — README updated to reflect actual directory structure and Phase 3 status
- ✅ FIXED 2026-04-02 — `.gitignore` updated to exclude `.DS_Store`
