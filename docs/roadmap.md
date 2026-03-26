# Development Roadmap — Zero Trust K8s

## Phase 1 — Baseline + Audit Engine + Violation Detection

### Deliverables
- ZeroTrustPolicy CRD defined and registered in the cluster
- Go project scaffolded with Kubebuilder
- Baseline loader reads CRD into in-memory Policy Store
- RBAC detector implemented: RBAC-001, RBAC-002, RBAC-003
- NetworkPolicy detector implemented: NP-001
- ViolationEvents printed as structured JSON to stdout
- System runs successfully against minikube cluster and detects real violations

### Dependencies
- Go installed and working
- minikube running and healthy
- Kubebuilder CLI installed
- kubectl configured to point at minikube

### Risks
- Go syntax and toolchain unfamiliarity — mitigate by having Cursor scaffold all boilerplate. Focus understanding on detector logic, not framework setup.
- CRD schema design decisions made now are expensive to change later — finalize the ZeroTrustPolicy spec before writing controller code.

---

## Phase 2 — Controller Loop + Remediation Engine

### Deliverables
- Remediation decision engine implemented with full decision matrix
- AutoFix for NP-001: apply default-deny NetworkPolicy to unprotected namespace
- AutoFix for RBAC-001 low-risk: remove wildcard verb via patch
- Escalation records written to audit log ConfigMap with full context
- Rate limiting implemented and tested
- Dry-run mode working and verified
- Pre-remediation snapshots written to audit log before every write
- Rollback procedure documented and manually tested

### Dependencies
- Phase 1 complete
- ZeroTrustPolicy CRD schema finalized (do not change schema after Phase 2 begins)

### Risks
- Autofix writes could break test workloads if applied to wrong namespace. Mitigate by testing exclusively in isolated minikube namespaces with no critical workloads.
- Decision matrix edge cases. Implement dry-run first, validate all decisions are correct before enabling auto mode.

---

## Phase 3 — Evaluation Harness + Metrics

### Deliverables
- Prometheus metrics endpoint live and scraping correctly
- All test scenarios from evaluation plan implemented as scripts in `evaluations/scenarios/`
- All 5 metrics measured and recorded with raw data
- False positive test suite passing (0 FP on exempt resources)
- Performance baseline documented
- Availability impact test run with HTTP server workload
- Evaluation results written to `evaluations/results.md`

### Dependencies
- Phase 2 complete and stable
- Prometheus deployed in minikube
- Test scenario scripts written before running any measurements (don't measure ad-hoc)

### Risks
- Metrics instrumentation is tedious but not complex — budget time for it
- Availability impact test requires a running workload to be in place before remediation fires. Set this up at the start of Phase 3.

---

## Phase 4 — Hardening + Documentation

### Deliverables
- Edge cases handled: API server unavailable, empty cluster, all-exempt cluster, zero violations cluster
- Circuit breaker implemented and tested against Scenario 7
- README with complete setup and install instructions
- `docs/architecture.md` reviewed and finalized
- `docs/threat-model.md` reviewed and finalized
- `docs/evaluation-plan.md` updated with actual results
- Demo script written for capstone defense presentation
- All code commented sufficiently to explain logic during defense

### Dependencies
- Phase 3 complete with evaluation results in hand

### Rules for Phase 4
- Add no new features. Harden and document only what exists.
- Every addition must serve the demo or the defense — if it doesn't, cut it.
