# Zero Trust K8s — Living Audit Checklist

This file is the authoritative record of every known bug, gap, unimplemented
spec item, and open question in the codebase. It is maintained by the Claude.ai
project ("Zero trust architecture for Kubernetes capstone") and updated after
every fix session.

**Rules:**
- Before writing any Cursor/Claude Code prompt, check this file first
- After every fix is confirmed in the repo, mark the item FIXED with date
- Never delete items — only change their status
- Items without a status are open

---

## OPEN

No open items. All known issues fixed as of 2026-04-18. Next: three-tool audit round.

---

## FIXED

*(Items move here once confirmed in the repo with date. Never deleted — only status changes.)*

### 2026-04-18 — Layer 2 Go fixes (L2-1, L2-2, L2-3)
- ✅ FIXED 2026-04-18 — L2-1: Added `mu sync.Mutex` to `ZeroTrustPolicyReconciler` struct;
  `r.mu.Lock()` / `defer r.mu.Unlock()` acquired at top of `Reconcile()` after cycleStart/defer
  lines; protects `seenViolations`, `rateLimitWindowStart`, `rateLimitWindowCount` from concurrent
  access in multi-replica or leader-transition scenarios
- ✅ FIXED 2026-04-18 — L2-2: Removed all 9 `logViolation()` calls from `detection.go`;
  added single `for _, event := range newEvents` loop in `Reconcile()` after the new/known
  split that calls `logViolation()` per new event only; steady-state stdout is now silent
  when `new_violations: 0`
- ✅ FIXED 2026-04-18 — L2-3: Added `"context"` and `"errors"` imports to `cmd/main.go`;
  `mgr.Start()` error block now checks `errors.Is(err, context.Canceled)` and exits 0
  for graceful SIGINT/SIGTERM shutdown; only unexpected errors exit 1

### 2026-04-18 — Layer 2 partial fixes (non-Go files)
- ✅ FIXED 2026-04-18 — V-4: `config/manager/manager.yaml` now injects `NAMESPACE` env var via
  Kubernetes downward API (`metadata.namespace`); audit log namespace is correct for both
  `make run` (falls back to `zerotrust-system`) and `make deploy` (reads actual pod namespace)
- ✅ FIXED 2026-04-18 — `evaluations/results.md` Known Limitations updated: stale reference to
  AUDIT_CHECKLIST item B (closed April 16) replaced with accurate description of retry behavior;
  stale reference to AUDIT_CHECKLIST item A (closed April 16) replaced with forward-looking
  note about mixed violation set re-run

### 2026-04-01
- ✅ FIXED 2026-04-01 — ConfigMap optimistic concurrency conflict: main loop now batches all
  audit entries into single `AppendAuditEntries` call after the for loop; eliminates per-entry
  write conflicts
- ✅ FIXED 2026-04-01 — `02-detect-rbac001.sh` timeout: extended to 90s, searches all
  ConfigMap data keys via python3 JSON parsing

### 2026-04-02
- ✅ FIXED 2026-04-02 — `setup.sh` now auto-deletes audit log ConfigMap on startup to
  prevent 1MB overflow across sessions
- ✅ FIXED 2026-04-02 — README updated to reflect actual directory structure and Phase 3 status
- ✅ FIXED 2026-04-02 — `.gitignore` updated to exclude `.DS_Store`

### 2026-04-09 — Correctness audit fixes (C-series, H-series, M-series, NF-series)
- ✅ FIXED 2026-04-09 — C-1: `RequireApprovalFor` enforced in `Decide()` via `approvalRequired()`
  helper; checked before mode overrides
- ✅ FIXED 2026-04-09 — C-2: NP-001 checks for genuine default-deny ingress via
  `hasDefaultDenyIngress()`; presence of any NetworkPolicy is no longer sufficient
- ✅ FIXED 2026-04-09 — C-3: `applyRemediation` returns `*AuditEntry`; no inline
  `AppendAuditEntry` calls; all writes flow through single batch call
- ✅ FIXED 2026-04-09 — C-4: RBAC-003 now iterates namespaced RoleBindings to cluster-admin
  in addition to ClusterRoleBindings
- ✅ FIXED 2026-04-09 — H-1: Event-driven watches added for ClusterRole, ClusterRoleBinding,
  RoleBinding, NetworkPolicy, Namespace; reduces worst-case detection latency from 30s to ~0s
- ✅ FIXED 2026-04-09 — H-2: `RecordEscalation` moved to after `AppendAuditEntries` succeeds;
  prevents double-counting on retry
- ✅ FIXED 2026-04-09 — H-3: `RateLimit` field comment corrected to "per reconcile cycle (30s)"
- ✅ FIXED 2026-04-09 — H-4: `buildAuditEntryID` uses nanosecond-precision timestamps to
  prevent duplicate EntryIDs in burst scenarios
- ✅ FIXED 2026-04-09 — H-5: Dead `json.Marshal(ns)` call removed from
  `applyDefaultDenyIngressForNP001`
- ✅ FIXED 2026-04-09 — M-1: RBAC-004 detector implemented (namespaced Role wildcard verbs,
  always HIGH risk)
- ✅ FIXED 2026-04-09 — M-2: RBAC-005 detector implemented (namespaced Role wildcard resources,
  always HIGH risk)
- ✅ FIXED 2026-04-09 — M-3: NP-002 detector implemented (missing default-deny egress,
  detection-only, no autofix)
- ✅ FIXED 2026-04-09 — NF-1: `autoFixedCount++` gated on non-nil `remAuditEntry`; no-op
  returns do not consume rate limit budget or inflate metrics
- ✅ FIXED 2026-04-09 — NF-2: `RecordRemediation` moved to post-`AppendAuditEntries` loop,
  mirrors escalation pattern for consistency
- ✅ FIXED 2026-04-09 — NF-3: `np001Risk` converted to method; checks pod phase
  (Running/Pending → HIGH, empty → LOW)
- ✅ FIXED 2026-04-09 — NF-4: RBAC-001 autofix returns `nil, nil` when `*` is sole verb;
  no invented verbs (later superseded by V-1 which returns SKIPPED instead)
- ✅ FIXED 2026-04-09 — NF-5: `hasDefaultDenyIngress` accepts implicit default-deny
  (empty `policyTypes` + no ingress rules = valid default-deny)
- ✅ FIXED 2026-04-09 — NF-6: `results.md` Metric 3 Test 2 description corrected; stale
  Known Limitations note updated
- ✅ FIXED 2026-04-09 — NF-8: `kube-system` guard in `applyRemediation` annotated as
  intentional defense-in-depth; do not remove

### 2026-04-16 — Round 1 post-audit fixes
- ✅ FIXED 2026-04-16 — Audit log verbosity regression: decision loop now iterates `newEvents`
  only; known persistent violations no longer written to audit ConfigMap every cycle
- ✅ FIXED 2026-04-16 — Rate limit regression: replaced per-cycle `autoFixedCount >= rateLimit`
  gate with `windowRateLimit()` method using a 30-second time window; budget now shared across
  all rapid reconcile cycles within a single window
- ✅ FIXED 2026-04-16 — M-4: Added `DenyWildcardResources *bool` as independent CRD field in
  `RBACSpec`; RBAC-001/RBAC-004 gated on `DenyWildcardVerbs`, RBAC-002/RBAC-005 gated on
  `DenyWildcardResources`; each independently toggleable
- ✅ FIXED 2026-04-16 — L-2: Integration test expanded with two new `It()` blocks: RBAC-001
  assertion on wildcard-verb ClusterRole injection, NP-001 assertion on NetworkPolicy-free
  namespace creation; all 3/3 specs pass via envtest
- ✅ FIXED 2026-04-16 — L-3: `AuditComplete` metav1.Condition written to ZeroTrustPolicy
  status after every successful reconcile cycle using `apimeta.SetStatusCondition`;
  idempotent upsert, non-fatal on failure
- ✅ FIXED 2026-04-16 — L-4: `detectRequireNamespacedRoles` implemented as RBAC-006 detector;
  scans ClusterRoleBindings for non-system subjects bound to non-system ClusterRoles; wired
  into `runDetections` behind the `RequireNamespacedRoles` flag; detection-only, LOW risk
- ✅ FIXED 2026-04-16 — NF-7: Replaced O(N namespace) per-namespace RoleBinding loop in
  `clusterRoleHasBindings` with a single cluster-wide `r.List(ctx, &rbList)` + in-memory
  filter; O(1) API calls regardless of namespace count

### 2026-04-16 — Round 2 post-audit fixes
- ✅ FIXED 2026-04-16 — A: Rate limit now applied inside `DecisionActionAutoFix` case only;
  ESCALATE/SKIP/DRY_RUN decisions no longer consume the 30-second remediation budget;
  HIGH-risk escalations cannot starve LOW-risk auto-fixes
- ✅ FIXED 2026-04-16 — B: `seenViolations` updated in post-`AppendAuditEntries` loop only;
  audit trail is eventually consistent — a failed write causes the violation to be
  re-processed on the next retry cycle rather than silently dropped
- ✅ FIXED 2026-04-16 — C: RBAC-003 deduplication now tracks per-subject via
  `SubjectName`/`SubjectKind` in both `ViolationKey` and `ViolationEvent`; a binding with
  N non-whitelisted subjects produces N distinct deduplication keys
- ✅ FIXED 2026-04-16 — D: Audit log now rotates to new ConfigMap objects
  (`ztk8s-audit-log-2`, etc.) when active object approaches 850KB; stays safely under
  Kubernetes 1 MiB per-object limit; `nextAuditKey`/`parseAuditKeyIndex`/`auditKeyForIndex`
  removed
- ✅ FIXED 2026-04-16 — E: Added `Watches(&rbacv1.Role{}, enqueueBaseline)` in
  `SetupWithManager`; RBAC-004/005 violations now detected event-driven immediately on
  Role create/update
- ✅ FIXED 2026-04-16 — F: Added `zerotrust-system` to `exemptNamespaces` in sample CR;
  controller no longer audits or auto-remediates its own namespace
- ✅ FIXED 2026-04-16 — G: `detectWildcardNamespacedRoles` replaced O(N namespaces) loop
  with single cluster-wide `r.List(ctx, &roleList)` + in-memory namespace filter;
  `detectClusterAdminBindings` namespaced portion replaced with single
  `r.List(ctx, &allRBList)`; both now O(1) API calls
- ✅ FIXED 2026-04-16 — H: Added explicit `case` branches for RBAC-004, RBAC-005, RBAC-006,
  and NP-002 in `decisionFromMatrix()`; all produce accurate `Reason` strings instead of
  falling through to the generic "unmapped violation type" default
- ✅ FIXED 2026-04-16 — I: `results.md` Metric 1 scope note clarified; Metric 5 description
  corrected — scenario tests detection/escalation in live-workload namespace, not
  auto-remediation; Metric 4 note added about homogeneous violation set scope
- ✅ FIXED 2026-04-16 — J: `remediationAuditEntryID` updated to nanosecond-precision
  timestamp format (`20060102150405.000000000`); matches `buildAuditEntryID` precision;
  H-4 fix was previously half-applied
- ✅ FIXED 2026-04-16 — K: Added `ztk8s_dryrun_total` and `ztk8s_skipped_total` Prometheus
  counters with `{violation_type, namespace}` labels; registered in metrics `init()`;
  `RecordDryRun()` and `RecordSkipped()` called in post-audit metrics loop
- ✅ FIXED 2026-04-16 — L: `results.md` Known Limitations audit retry paragraph corrected
  to accurately describe the seenViolations ordering behavior (superseded by fix B above)
- ✅ FIXED 2026-04-16 — M: Added `Watches(&corev1.Pod{}, enqueueBaseline)` in
  `SetupWithManager`; NP-001 risk transitions (empty → running namespace) now detected
  event-driven
- ✅ FIXED 2026-04-16 — N: `auditLogConfigMapNamespace` changed from compile-time constant
  to package-level variable with `defaultAuditNamespace` fallback; `SetAuditNamespace()`
  reads `NAMESPACE` env var in `cmd/main.go` before manager starts

### 2026-04-16 — Generated file sync and setup improvements
- ✅ FIXED 2026-04-16 — `zz_generated.deepcopy.go` regenerated via `make generate` to
  include `DenyWildcardResources *bool` field in `RBACSpec.DeepCopyInto`; was missing
  since M-4 added the Go type
- ✅ FIXED 2026-04-16 — `config/crd/bases/zerotrust.capstone.io_zerotrustpolicies.yaml`
  regenerated via `make manifests` to include `denyWildcardResources` in CRD OpenAPI schema
- ✅ FIXED 2026-04-16 — `setup.sh` updated to delete all numbered audit ConfigMaps
  (`ztk8s-audit-log-2` through `-20`) on session reset, not just the base ConfigMap

### 2026-04-16 — Round 3 verification fixes
- ✅ FIXED 2026-04-16 — V-1: `removeWildcardVerbsForRBAC001Low` `!safeToFix` branch now
  returns `*AuditEntry` with `Action: "SKIPPED"` instead of `(nil, nil)`; audit entry
  written to ConfigMap, `ztk8s_skipped_total` incremented, rate limit token NOT consumed
  (no-op does not decrement budget); Scenario 02 and Test B now produce an audit trail
- ✅ FIXED 2026-04-16 — V-2: `Reconcile()` re-fetches `freshPolicy` via `r.Get()` immediately
  before `r.Status().Update()`; eliminates ~5% of cycles logging "the object has been
  modified" under event-driven watch bursts; standard controller-runtime pattern
- ✅ FIXED 2026-04-16 — V-3: `AppendAuditEntries` checks `currentSize + pendingSize >=
  auditLogMaxObjectBytes` before writing; rotates proactively to next ConfigMap object if
  batch would overflow threshold; closes race window in previous reactive-only check
- ✅ FIXED 2026-04-16 — `setup.sh` now also cleans stale `eval-rbac001-*` ClusterRoles
  accumulated from failed Scenario 02 runs in prior sessions
