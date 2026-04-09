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
`RoleBinding` that references `cluster-admin` as its roleRef is completely invisible to this
detector. Confirmed by code review: no `RoleBindingList` loop exists in `detectClusterAdminBindings`.  
**Fix:** After the ClusterRoleBinding loop, iterate all namespaces and list `RoleBindingList`
per namespace, checking `roleRef.name == "cluster-admin"` using the same exclusion logic.

---

## HIGH — Fix Soon, Before New Feature Work

### H-1 — Controller has no watches on audited resource types
**File:** `internal/controller/zerotrustpolicy_controller.go`, `SetupWithManager`  
**Status:** 🔴 OPEN  
**Description:** `SetupWithManager` only calls `.For(&ZeroTrustPolicy{})`. No watches on
`ClusterRole`, `ClusterRoleBinding`, `NetworkPolicy`, or `Namespace`. Misconfigurations
introduced between 30-second cycles go undetected until the next poll.  
**Fix:** Add `.Watches()` calls for ClusterRole, ClusterRoleBinding, NetworkPolicy, and Namespace
with an `EnqueueRequestsFromMapFunc` that always returns the cluster-baseline key.

### NF-1 — `RecordRemediation` and `autoFixedCount++` fire even when `applyRemediation` returns `(nil, nil)`
**File:** `internal/controller/zerotrustpolicy_controller.go`, AUTO_FIX case  
**Status:** 🔴 OPEN  
**Description:** After the `if remAuditEntry != nil` block, `RecordRemediation` and
`autoFixedCount++` execute unconditionally — even when `applyRemediation` returned nil
(idempotent no-op: namespace gone, role already clean, etc.). This overcounts remediation
metrics and consumes rate-limit budget for operations that did nothing.  
**Fix:** Move both `RecordRemediation(event.ViolationType, event.Namespace)` and `autoFixedCount++`
inside the `if remAuditEntry != nil` block. Mirror the escalation pattern exactly.

### NF-2 — `RecordRemediation` fires before `AppendAuditEntries` succeeds
**File:** `internal/controller/zerotrustpolicy_controller.go`, AUTO_FIX case  
**Status:** 🔴 OPEN  
**Description:** `RecordRemediation` is called inside the `AUTO_FIX` case (before the loop ends),
while `AppendAuditEntries` runs after the loop. If the audit write fails and the reconciler
retries, the Prometheus remediation counter has already been incremented but no audit record
exists. This is the same asymmetry that H-2 fixed for escalations.  
**Fix:** Remove `RecordRemediation` from the AUTO_FIX switch case. After `AppendAuditEntries`
succeeds, add a loop over `pendingAuditEntries` that calls `RecordRemediation` for entries
with `Action == "AUTO_REMEDIATED"` — identical pattern to the post-audit escalation loop.

### NF-3 — `np001Risk` ignores running pods; docs say HIGH for namespaces with active workloads
**File:** `internal/controller/detection.go`, `np001Risk`  
**Status:** 🔴 OPEN  
**Description:** `np001Risk` returns `"LOW"` for every non-kube-system namespace with zero
pod check. `docs/remediation-model.md` says `NP-001 | HIGH | Has running pods | ESCALATE`.
A namespace with live microservices will be silently auto-remediated (default-deny applied)
instead of escalated for human review.  
**Fix:** In `np001Risk`, list pods in the namespace. If any pod is in `Running` or `Pending`
phase, return `"HIGH"`. Only return `"LOW"` for empty namespaces.

### NF-4 — RBAC-001 autofix invents `get,list,watch` when `*` is the only verb
**File:** `internal/controller/remediation.go`, `removeWildcardVerbsForRBAC001Low`  
**Status:** 🔴 OPEN  
**Description:** `if len(filtered) == 0 { filtered = []string{"get", "list", "watch"} }` —
when a rule contains only `verbs: ["*"]`, removing the wildcard leaves an empty slice, and the
code silently substitutes read-only verbs. This invents an unintended permission set and can
break workloads or preserve more access than intended.  
**Fix:** When `len(filtered) == 0` after wildcard removal, do NOT apply a fallback verb set.
Instead return `nil, nil` so the caller treats this as a no-op that escalates via the rate-limit
path. Add a `DEFENSE NOTE` explaining why inventing verbs is unsafe.

---

## MEDIUM — Detection Breadth and Correctness

### M-1 — RBAC-004 not implemented (namespaced Role wildcard verbs)
**File:** `internal/controller/detection.go`  
**Status:** 🔴 OPEN  
**Description:** Wildcard verb detection on namespaced `Role` objects. Only ClusterRoles scanned.

### M-2 — RBAC-005 not implemented (namespaced Role wildcard resources)
**File:** `internal/controller/detection.go`  
**Status:** 🔴 OPEN  
**Description:** Wildcard resource detection on namespaced `Role` objects. Only ClusterRoles scanned.

### M-3 — NP-002 not implemented (missing default-deny egress)
**File:** `internal/controller/detection.go`  
**Status:** 🔴 OPEN  
**Description:** `spec.networkPolicy.requireDefaultDenyEgress` is a CRD field that is read
but never acted upon. No egress NetworkPolicy detector exists.

### M-4 — `DenyWildcardVerbs` flag silently controls RBAC-002 detection
**File:** `internal/controller/detection.go`  
**Status:** 🟡 WARN  
**Description:** Both `hasWildcardVerb` and `hasWildcardResource` are checked under the single
`DenyWildcardVerbs` flag. RBAC-002 cannot be independently toggled. CRD design inconsistency.

### NF-5 — `hasDefaultDenyIngress` rejects implicit default-deny (omitted `policyTypes`)
**File:** `internal/controller/detection.go`, `hasDefaultDenyIngress`  
**Status:** 🔴 OPEN  
**Description:** Criterion 2 requires `PolicyTypeIngress` to be explicitly present in
`spec.policyTypes`. Kubernetes docs state that when `policyTypes` is omitted and the policy
has no ingress rules, it is treated as an implicit default-deny ingress. Clusters with
pre-existing default-deny policies written without explicit `policyTypes` (common in older
manifests) will receive false-positive NP-001 violations and duplicate remediation writes.  
**Fix:** In `hasDefaultDenyIngress`, add fallback: if `len(pol.Spec.PolicyTypes) == 0` AND
`len(pol.Spec.Ingress) == 0`, treat as implicit ingress default-deny and return true.

### NF-6 — `results.md` false-positive test description does not match the script
**File:** `evaluations/results.md`, `evaluations/scenarios/03-false-positive.sh`  
**Status:** 🔴 OPEN  
**Description:** The results table for Metric 3 (False Positive Rate) states Test 2 verified
"Excluded ClusterRole — No RBAC-001 violation". The actual script checks "kube-system namespace
should not be auto-remediated for NP-001". The documented test was never run. This overstates
evaluation coverage.  
**Fix:** Update `results.md` row 2 to accurately describe what was actually measured
("kube-system NP-001 not auto-remediated"). Optionally add a proper excluded-ClusterRole
test to 03-false-positive.sh.

---

## LOW — Polish, Scalability, and Test Coverage

### L-1 — envtest binaries not set up, `go test` fails
**File:** `Makefile` target `setup-envtest`  
**Status:** ✅ FIXED (confirmed by Cursor and Codex in audit)  

### L-2 — Controller integration test only asserts RequeueAfter, no violation detection
**File:** `internal/controller/zerotrustpolicy_controller_test.go`  
**Status:** 🟡 WARN  
**Fix:** Add two `It()` blocks: one ClusterRole with `verbs: ["*"]` asserting RBAC-001;
one namespace with no NetworkPolicy asserting NP-001.

### L-3 — `ZeroTrustPolicyStatus` conditions never written
**File:** `internal/controller/zerotrustpolicy_controller.go`  
**Status:** 🟡 WARN  
**Fix:** After cycle summary log, write a `metav1.Condition` of type `AuditComplete`.

### L-4 — `RequireNamespacedRoles` field defined but never enforced
**File:** `api/v1alpha1/zerotrustpolicy_types.go`, `internal/controller/detection.go`  
**Status:** 🔴 OPEN (confirmed by code review — no check exists in runDetections)

### NF-7 — `clusterRoleHasBindings` issues one API call per namespace (scalability)
**File:** `internal/controller/detection.go`, `clusterRoleHasBindings`  
**Status:** 🟡 WARN  
**Description:** The per-namespace RoleBinding loop calls `r.List(ctx, &rbList, client.InNamespace(nsName))`
inside a namespace iteration loop — one API call per namespace. On a 50-namespace cluster this
is 50 API calls per RBAC-001 violation per cycle. Replace with a single cluster-wide
`r.List(ctx, &rbList)` (no InNamespace option) then filter in memory.

### NF-8 — `kube-system` guard in `applyRemediation` is belt-and-suspenders (doc-only)
**File:** `internal/controller/remediation.go`, `applyRemediation`  
**Status:** 🟡 WARN  
**Description:** kube-system gets `CRITICAL` from `np001Risk` → `SKIP` from the decision matrix
→ never reaches `applyRemediation`. The guard is unreachable via normal code paths but is
intentional defense-in-depth. Add a `// DEFENSE NOTE` comment making this explicit so future
readers don't remove it thinking it's dead code.

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
