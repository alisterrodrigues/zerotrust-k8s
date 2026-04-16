# Development Roadmap — Zero Trust K8s

## Phase 1 — Baseline + Audit Engine + Violation Detection ✅ COMPLETE

### Deliverables
- ZeroTrustPolicy CRD defined and registered in the cluster
- Go project scaffolded with Kubebuilder v4
- RBAC detectors: RBAC-001, RBAC-002, RBAC-003
- NetworkPolicy detector: NP-001
- ViolationEvents printed as structured JSON to stdout
- envtest integration test suite (Ginkgo/Gomega)
- System runs against minikube cluster and detects real violations

---

## Phase 2 — Controller Loop + Remediation Engine ✅ COMPLETE

### Deliverables
- Remediation decision engine with full decision matrix (`internal/controller/decision.go`)
- AutoFix for NP-001 LOW: apply `ztk8s-default-deny-ingress` NetworkPolicy (Server-Side Apply)
- AutoFix for RBAC-001 LOW: remove wildcard verbs via Update (skips if `*` is sole verb)
- Escalation records written to `ztk8s-audit-log` ConfigMap with full context
- Batch audit write — single ConfigMap update per reconcile cycle
- Time-window rate limiting (30s window, default 5 remediations)
- Dry-run mode and manual mode working and verified
- Pre-remediation snapshots in audit log before every write
- `requireApprovalFor` CRD field enforced in decision engine

---

## Phase 3 — Observability + Evaluation ✅ COMPLETE

### Deliverables
- Prometheus metrics: `ztk8s_violations_total`, `ztk8s_remediations_total`, `ztk8s_escalations_total`, `ztk8s_cycle_duration_seconds`
- Metrics exposed at `:8080/metrics` (plain HTTP)
- Violation deduplication via in-memory `seenViolations` map
- Event-driven watches for ClusterRole, ClusterRoleBinding, RoleBinding, NetworkPolicy, Namespace
- All 5 evaluation metrics measured and recorded in `evaluations/results.md`
- False positive test suite passing (0 FP on exempt resources)

---

## Post-Audit Hardening ✅ COMPLETE (2026-04-16)

### Deliverables
- **RBAC-004**: Wildcard verb detection on namespaced Roles
- **RBAC-005**: Wildcard resource detection on namespaced Roles
- **RBAC-006**: RequireNamespacedRoles enforcement (non-system CRB detector)
- **NP-002**: Default-deny egress detection (detection-only)
- **`denyWildcardResources`**: Independent CRD field added to `RBACSpec`; RBAC-002/005 now separately toggleable from RBAC-001/004
- **`AuditComplete` status condition**: Written to ZeroTrustPolicy after every successful cycle
- **Scalability fix**: `clusterRoleHasBindings` now uses single cluster-wide RoleBinding List (O(1) API calls)
- **Audit log verbosity fix**: Decision loop iterates `newEvents` only — known violations no longer re-written every cycle
- **Rate limit fix**: Per-cycle counter replaced with 30-second time-window counter
- **Integration test expansion**: Two new `It()` blocks asserting RBAC-001 and NP-001 detection end-to-end

---

## Phase 4 — Final Report + Defense Prep (Upcoming)

### Deliverables
- Final capstone report covering all phases, post-audit hardening, and evaluation
- Defense presentation and demo script
- All `// DEFENSE NOTE` comments reviewed for talking points
- Documentation final review

### Rules for Phase 4
- Add no new features. Consolidate and document only what exists.
- Every addition must serve the defense or the final report.
