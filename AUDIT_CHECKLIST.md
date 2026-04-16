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

## OPEN ITEMS

No open items remain as of 2026-04-16 (Round 2 audit). All known bugs, gaps,
and checklist items have been resolved. The next additions will come from a
third-round audit run against the post-fix codebase.

---

## FIXED

*(Items move here once confirmed in the repo with date)*

- FIXED 2026-04-01 — ConfigMap optimistic concurrency conflict: main loop now batches all
  audit entries into single AppendAuditEntries call after the for loop
- FIXED 2026-04-01 — 02-detect-rbac001.sh timeout: extended to 90s, searches all
  ConfigMap data keys via python3 JSON parsing
- FIXED 2026-04-02 — setup.sh now auto-deletes audit log ConfigMap on startup to
  prevent 1MB overflow across sessions
- FIXED 2026-04-02 — README updated to reflect actual directory structure and Phase 3 status
- FIXED 2026-04-02 — .gitignore updated to exclude .DS_Store
- FIXED 2026-04-09 — C-1: RequireApprovalFor enforced in Decide() via approvalRequired() helper
- FIXED 2026-04-09 — C-2: NP-001 checks for default-deny ingress via hasDefaultDenyIngress()
- FIXED 2026-04-09 — C-3: applyRemediation returns *AuditEntry; no inline AppendAuditEntry calls
- FIXED 2026-04-09 — C-4: RBAC-003 now iterates namespaced RoleBindings to cluster-admin
- FIXED 2026-04-09 — H-1: Event-driven watches added for ClusterRole, ClusterRoleBinding, RoleBinding, NetworkPolicy, Namespace
- FIXED 2026-04-09 — H-2: RecordEscalation moved to after AppendAuditEntries succeeds
- FIXED 2026-04-09 — H-3: RateLimit field comment corrected to "per reconcile cycle (30s)"
- FIXED 2026-04-09 — H-4: buildAuditEntryID uses nanosecond-precision timestamps
- FIXED 2026-04-09 — H-5: Dead json.Marshal(ns) call removed from applyDefaultDenyIngressForNP001
- FIXED 2026-04-09 — M-1: RBAC-004 detector implemented (namespaced Role wildcard verbs, HIGH)
- FIXED 2026-04-09 — M-2: RBAC-005 detector implemented (namespaced Role wildcard resources, HIGH)
- FIXED 2026-04-09 — M-3: NP-002 detector implemented (missing default-deny egress, detection-only)
- FIXED 2026-04-09 — NF-1: autoFixedCount++ gated on non-nil remAuditEntry (no-ops don't consume rate limit)
- FIXED 2026-04-09 — NF-2: RecordRemediation moved to post-AppendAuditEntries loop, mirrors escalation pattern
- FIXED 2026-04-09 — NF-3: np001Risk converted to method; checks pod phase (Running/Pending -> HIGH)
- FIXED 2026-04-09 — NF-4: RBAC-001 autofix returns nil, nil when * is sole verb; no invented verbs
- FIXED 2026-04-09 — NF-5: hasDefaultDenyIngress accepts implicit default-deny (empty policyTypes)
- FIXED 2026-04-09 — NF-6: results.md Metric 3 Test 2 description corrected; stale Known Limitations note updated
- FIXED 2026-04-09 — NF-8: kube-system guard in applyRemediation annotated as intentional defense-in-depth
- FIXED 2026-04-16 (Round 1) — Audit log verbosity regression: decision loop now iterates newEvents only
- FIXED 2026-04-16 (Round 1) — Rate limit regression: replaced per-cycle counter with 30-second time-window counter via windowRateLimit()
- FIXED 2026-04-16 (Round 1) — M-4: Added DenyWildcardResources *bool as independent CRD field in RBACSpec
- FIXED 2026-04-16 (Round 1) — L-2: Integration test expanded with RBAC-001 and NP-001 detection assertions; 3/3 specs pass
- FIXED 2026-04-16 (Round 1) — L-3: AuditComplete metav1.Condition written to ZeroTrustPolicy status after every cycle
- FIXED 2026-04-16 (Round 1) — L-4: detectRequireNamespacedRoles implemented as RBAC-006 detector
- FIXED 2026-04-16 (Round 1) — NF-7: clusterRoleHasBindings replaced O(N namespace) loop with single cluster-wide RoleBindingList
- FIXED 2026-04-16 (Round 2) — A: Rate limit now applied inside DecisionActionAutoFix case only;
  ESCALATE/SKIP/DRY_RUN decisions no longer consume the 30-second remediation budget.
  HIGH-risk escalations cannot starve LOW-risk auto-fixes.
- FIXED 2026-04-16 (Round 2) — B: seenViolations updated in post-AppendAuditEntries loop only;
  audit trail is eventually consistent — a failed write causes the violation to be re-processed
  on the next retry cycle rather than silently dropped.
- FIXED 2026-04-16 (Round 2) — C: RBAC-003 deduplication now tracks per-subject via SubjectName/SubjectKind
  in both ViolationKey and ViolationEvent; a binding with N non-whitelisted subjects produces N
  distinct deduplication keys instead of collapsing into one.
- FIXED 2026-04-16 (Round 2) — D: Audit log now rotates to new ConfigMap objects (ztk8s-audit-log-2, etc.)
  when active object approaches 850 KB; stays safely under Kubernetes 1 MiB per-object limit.
  currentAuditConfigMapName() manages rotation; nextAuditKey/parseAuditKeyIndex/auditKeyForIndex removed.
- FIXED 2026-04-16 (Round 2) — E: Added Watches(&rbacv1.Role{}, enqueueBaseline) in SetupWithManager;
  RBAC-004/005 violations are now detected event-driven immediately on Role create/update.
- FIXED 2026-04-16 (Round 2) — F: Added zerotrust-system to exemptNamespaces in sample CR;
  controller no longer audits or auto-remediates its own namespace.
- FIXED 2026-04-16 (Round 2) — G: detectWildcardNamespacedRoles replaced O(N namespaces) loop with
  single cluster-wide r.List(ctx, &roleList) + in-memory namespace filter.
  detectClusterAdminBindings namespaced portion replaced with single r.List(ctx, &allRBList).
  Both now O(1) API calls regardless of namespace count — mirrors NF-7 fix from Round 1.
- FIXED 2026-04-16 (Round 2) — H: Added explicit case branches for RBAC-004, RBAC-005, RBAC-006,
  and NP-002 in decisionFromMatrix(); all produce accurate Reason strings instead of falling
  through to the generic "unmapped violation type" default.
- FIXED 2026-04-16 (Round 2) — I: results.md Metric 1 scope note clarified; Metric 5 description
  corrected — scenario tests detection/escalation in live-workload namespace, not auto-remediation.
  Metric 4 note added about homogeneous violation set scope.
- FIXED 2026-04-16 (Round 2) — J: remediationAuditEntryID updated to nanosecond-precision timestamp
  format (20060102150405.000000000); matches buildAuditEntryID precision. H-4 fix was half-applied.
- FIXED 2026-04-16 (Round 2) — K: Added ztk8s_dryrun_total and ztk8s_skipped_total Prometheus counters
  with {violation_type, namespace} labels; registered in metrics init(); RecordDryRun() and
  RecordSkipped() called in post-audit metrics loop. Operators can now confirm detection pipeline
  activity in dryrun and manual modes.
- FIXED 2026-04-16 (Round 2) — L: results.md Known Limitations audit retry paragraph corrected —
  documents that failed audit writes lose the entry for that cycle (seenViolations already updated).
  This limitation is itself resolved by fix B above; the Known Limitations note updated to reflect
  the current correct behavior.
- FIXED 2026-04-16 (Round 2) — M: Added Watches(&corev1.Pod{}, enqueueBaseline) in SetupWithManager;
  NP-001 risk transitions (empty -> running namespace) now detected event-driven.
- FIXED 2026-04-16 (Round 2) — N: auditLogConfigMapNamespace changed from compile-time constant to
  package-level variable with defaultAuditNamespace fallback. SetAuditNamespace() reads NAMESPACE
  env var in cmd/main.go before manager starts. Audit log namespace now matches deployment namespace
  in any deployment model (make run or make deploy).
