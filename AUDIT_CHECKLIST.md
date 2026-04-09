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
- ✅ FIXED 2026-04-09 — C-1: `RequireApprovalFor` now enforced in `Decide()` via `approvalRequired()` helper with alias map
- ✅ FIXED 2026-04-09 — C-2: NP-001 now checks for default-deny ingress specifically via `hasDefaultDenyIngress()`, not just any NetworkPolicy
- ✅ FIXED 2026-04-09 — C-3: `applyRemediation` now returns `*AuditEntry` to caller; no more individual `AppendAuditEntry` calls in remediation path
- ✅ FIXED 2026-04-09 — H-2: `RecordEscalation` moved to after `AppendAuditEntries` succeeds
- ✅ FIXED 2026-04-09 — H-3: `RateLimit` field comment corrected to "per reconcile cycle (default interval: 30 seconds)"
- ✅ FIXED 2026-04-09 — H-4: `buildAuditEntryID` now uses nanosecond-precision timestamps
- ✅ FIXED 2026-04-09 — H-5: Dead `json.Marshal(ns)` call removed from `applyDefaultDenyIngressForNP001`
