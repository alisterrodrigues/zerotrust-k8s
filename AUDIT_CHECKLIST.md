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

## OPEN ITEMS

*No open items remain as of 2026-04-16. All known bugs, gaps, and checklist items
have been resolved. The next additions to this file will come from the second-round
audit (Cursor + Codex + ChatGPT) run against the post-fix codebase.*

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
- ✅ FIXED 2026-04-16 — Audit log verbosity regression: decision loop now iterates `newEvents` only;
  known persistent violations no longer written to audit ConfigMap every cycle
- ✅ FIXED 2026-04-16 — Rate limit regression: replaced per-cycle `autoFixedCount >= rateLimit` gate with
  `windowRateLimit()` method using a 30-second time window; budget now shared across all rapid reconcile
  cycles within a single window, correctly throttling event-driven watch bursts
- ✅ FIXED 2026-04-16 — M-4: Added `DenyWildcardResources *bool` as independent CRD field in `RBACSpec`;
  RBAC-001/RBAC-004 now gated on `DenyWildcardVerbs`, RBAC-002/RBAC-005 now gated on `DenyWildcardResources`;
  each check independently toggleable
- ✅ FIXED 2026-04-16 — L-2: Integration test expanded with two new `It()` blocks: RBAC-001 assertion on
  wildcard-verb ClusterRole injection, NP-001 assertion on NetworkPolicy-free namespace creation;
  all 3/3 specs pass via envtest
- ✅ FIXED 2026-04-16 — L-3: `AuditComplete` metav1.Condition written to ZeroTrustPolicy status after every
  successful reconcile cycle using `apimeta.SetStatusCondition`; idempotent upsert, non-fatal on failure
- ✅ FIXED 2026-04-16 — L-4: `detectRequireNamespacedRoles` implemented as RBAC-006 detector; scans
  ClusterRoleBindings for non-system subjects bound to non-system ClusterRoles; wired into `runDetections`
  behind the `RequireNamespacedRoles` flag; detection-only (no autofix), LOW risk
- ✅ FIXED 2026-04-16 — NF-7: Replaced O(N namespace) per-namespace RoleBinding loop in
  `clusterRoleHasBindings` with a single cluster-wide `r.List(ctx, &rbList)` + in-memory filter;
  O(1) API calls regardless of namespace count
