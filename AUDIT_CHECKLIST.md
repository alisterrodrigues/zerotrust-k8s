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

## MEDIUM — Open Items

### M-4 — `DenyWildcardVerbs` flag silently controls RBAC-002 detection
**File:** `internal/controller/detection.go`  
**Status:** 🟡 WARN  
**Description:** Both `hasWildcardVerb` and `hasWildcardResource` are checked under the single
`DenyWildcardVerbs` flag. RBAC-002 cannot be independently toggled. CRD design inconsistency.

---

## LOW — Polish, Scalability, and Test Coverage

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
**Description:** Per-namespace RoleBinding loop — one `r.List` call per namespace. Replace with
a single cluster-wide `r.List(ctx, &rbList)` then filter in memory for production scalability.

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
- ✅ FIXED 2026-04-09 — C-1: `RequireApprovalFor` enforced in `Decide()` via `approvalRequired()` helper
- ✅ FIXED 2026-04-09 — C-2: NP-001 checks for default-deny ingress via `hasDefaultDenyIngress()`
- ✅ FIXED 2026-04-09 — C-3: `applyRemediation` returns `*AuditEntry`; no inline `AppendAuditEntry` calls
- ✅ FIXED 2026-04-09 — C-4: RBAC-003 now iterates namespaced RoleBindings to cluster-admin
- ✅ FIXED 2026-04-09 — H-1: Event-driven watches added for ClusterRole, ClusterRoleBinding, RoleBinding, NetworkPolicy, Namespace
- ✅ FIXED 2026-04-09 — H-2: `RecordEscalation` moved to after `AppendAuditEntries` succeeds
- ✅ FIXED 2026-04-09 — H-3: `RateLimit` field comment corrected to "per reconcile cycle (30s)"
- ✅ FIXED 2026-04-09 — H-4: `buildAuditEntryID` uses nanosecond-precision timestamps
- ✅ FIXED 2026-04-09 — H-5: Dead `json.Marshal(ns)` call removed from `applyDefaultDenyIngressForNP001`
- ✅ FIXED 2026-04-09 — M-1: RBAC-004 detector implemented (namespaced Role wildcard verbs, HIGH)
- ✅ FIXED 2026-04-09 — M-2: RBAC-005 detector implemented (namespaced Role wildcard resources, HIGH)
- ✅ FIXED 2026-04-09 — M-3: NP-002 detector implemented (missing default-deny egress, detection-only)
- ✅ FIXED 2026-04-09 — NF-1: `autoFixedCount++` gated on non-nil `remAuditEntry` (no-ops don't consume rate limit)
- ✅ FIXED 2026-04-09 — NF-2: `RecordRemediation` moved to post-`AppendAuditEntries` loop, mirrors escalation pattern
- ✅ FIXED 2026-04-09 — NF-3: `np001Risk` converted to method; checks pod phase (Running/Pending → HIGH)
- ✅ FIXED 2026-04-09 — NF-4: RBAC-001 autofix returns `nil, nil` when `*` is sole verb; no invented verbs
- ✅ FIXED 2026-04-09 — NF-5: `hasDefaultDenyIngress` accepts implicit default-deny (empty `policyTypes`)
- ✅ FIXED 2026-04-09 — NF-6: `results.md` Metric 3 Test 2 description corrected; stale Known Limitations note updated
- ✅ FIXED 2026-04-09 — NF-8: `kube-system` guard in `applyRemediation` annotated as intentional defense-in-depth
