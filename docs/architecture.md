# Architecture — Zero Trust Policy Enforcement and Automated Misconfiguration Remediation System for Kubernetes

## System Vision

### What We Are Building
A Kubernetes-native security controller (ZeroTrust-K8s) that runs a continuous loop: watches RBAC and NetworkPolicy configurations, compares them against a formally defined Zero Trust baseline, and when it finds a gap either fixes it automatically or escalates it for human review with a structured recommendation.

The system runs as a controller — a long-running process that reconciles desired state (your Zero Trust baseline) with actual state (what's currently configured in the cluster). It is not a one-time scanner. It runs continuously, catching drift as it happens, and reacts immediately to cluster changes via event-driven watches.

### What Makes It Different from OPA/Kyverno
OPA and Kyverno are admission controllers — they sit at the door and decide whether to let new resources in. They are preventive. They do nothing about violations that already exist, configurations that drifted after admission, or legacy misconfigurations present before the tool was installed.

This system is corrective and continuous. It doesn't just block — it hunts, classifies, and fixes. The remediation decision engine is the intellectual contribution that neither OPA nor Kyverno has.

### Implemented Capability
The system currently:
- Loads a Zero Trust baseline from a YAML-defined CRD
- Scans all ClusterRoles, Roles, RoleBindings, ClusterRoleBindings, and NetworkPolicies
- Detects eight violation types across RBAC and network controls (RBAC-001 through RBAC-006, NP-001, NP-002)
- Classifies each violation as LOW, HIGH, or CRITICAL using a formal decision matrix
- Auto-applies a default-deny NetworkPolicy to unprotected empty namespaces (NP-001 LOW)
- Auto-removes wildcard verbs from non-system unbound ClusterRoles (RBAC-001 LOW)
- Escalates all other violations to the audit log for human review
- Writes structured JSON violation logs to stdout
- Exposes a `/metrics` endpoint with Prometheus counters and histograms
- Writes an `AuditComplete` status condition to the ZeroTrustPolicy resource after every cycle

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        KUBERNETES CLUSTER                        │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  ZeroTrust-K8s Controller                │   │
│  │                                                          │   │
│  │  ┌──────────────┐    ┌──────────────┐                   │   │
│  │  │   Baseline   │    │    Policy    │                   │   │
│  │  │    Loader    │───▶│    Store     │                   │   │
│  │  └──────────────┘    └──────┬───────┘                   │   │
│  │                             │                            │   │
│  │                             ▼                            │   │
│  │  ┌──────────────────────────────────────────────────┐   │   │
│  │  │                   Audit Engine                    │   │   │
│  │  │  ┌─────────────────┐  ┌────────────────────────┐ │   │   │
│  │  │  │  RBAC Detector  │  │ NetworkPolicy Detector  │ │   │   │
│  │  │  └────────┬────────┘  └──────────┬─────────────┘ │   │   │
│  │  └───────────┼──────────────────────┼───────────────┘   │   │
│  │              │                      │                    │   │
│  │              ▼                      ▼                    │   │
│  │  ┌─────────────────────────────────────────────────┐    │   │
│  │  │           Violation Detection Engine             │    │   │
│  │  │         (produces typed ViolationEvents)         │    │   │
│  │  └──────────────────────┬──────────────────────────┘    │   │
│  │                         │                               │   │
│  │                         ▼                               │   │
│  │  ┌─────────────────────────────────────────────────┐    │   │
│  │  │          Remediation Decision Engine             │    │   │
│  │  │   Risk Classification → Action Selection         │    │   │
│  │  └──────────┬──────────────────────┬───────────────┘    │   │
│  │             │                      │                     │   │
│  │             ▼                      ▼                     │   │
│  │  ┌──────────────────┐   ┌──────────────────────────┐    │   │
│  │  │  Auto-Remediate  │   │   Escalation Queue        │    │   │
│  │  │  (K8s API calls) │   │ (structured human alert)  │    │   │
│  │  └──────────────────┘   └──────────────────────────┘    │   │
│  │                                                          │   │
│  │  ┌─────────────────────────────────────────────────┐    │   │
│  │  │         Logging + Audit Trail + Metrics          │    │   │
│  │  └─────────────────────────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│  │  RBAC Objects│  │NetworkPolicies│  │ ZeroTrustPolicy CRDs  │ │
│  │  (live state)│  │  (live state) │  │   (desired state)     │ │
│  └──────────────┘  └──────────────┘  └───────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘

External:
┌──────────────────────┐    ┌─────────────────────────────────┐
│   Prometheus Server  │◀───│  /metrics endpoint (port 8080)  │
└──────────────────────┘    └─────────────────────────────────┘
┌──────────────────────┐
│  Human Reviewer      │◀─── Escalation alerts (audit log ConfigMap)
└──────────────────────┘
```

### Control Plane vs Data Plane
**Control plane** — the controller, the baseline CRD, the decision engine. This is where policy lives and decisions are made.

**Data plane** — the actual RBAC objects, NetworkPolicies, and running workloads. The controller reads and modifies these but never becomes them.

### End-to-End Event Flow
```
1.  Operator applies ZeroTrustPolicy CRD to cluster
2.  Baseline Loader reads CRD, populates Policy Store in memory
3.  Audit Engine starts reconciliation loop (every 30s by default,
    plus immediate trigger on any watched resource change)
4.  RBAC Detector queries Kubernetes API for all ClusterRoles,
    Roles, ClusterRoleBindings, RoleBindings
5.  NetworkPolicy Detector queries all namespaces and their
    NetworkPolicies
6.  Each result is compared against Policy Store rules
7.  Violations are emitted as typed ViolationEvent structs
8.  New violations (not seen before) are separated from known ones
9.  Remediation Decision Engine receives each new ViolationEvent
10. Risk classifier assigns LOW / HIGH / CRITICAL per decision matrix
11. LOW risk + auto mode → AutoRemediate() called → Kubernetes API write
12. HIGH/CRITICAL risk → Escalation record written to audit log
13. Mode overrides (dryrun/manual) and requireApprovalFor evaluated
14. Rate limit (windowRateLimit, 30s window) caps remediation burst
15. All new-event actions batched into single ConfigMap audit write
16. Prometheus metrics counters updated
17. AuditComplete status condition written to ZeroTrustPolicy
18. Loop requeues after 30s; event-driven watches trigger immediately
```

---

## Core Components

### Zero Trust Baseline Model
**Purpose:** Defines what a compliant cluster looks like. The source of truth.

**Implementation:** A `ZeroTrustPolicy` CRD applied by the operator. Go struct hierarchy in `api/v1alpha1/zerotrustpolicy_types.go` mirrors the CRD schema and is loaded by the reconciler at each cycle.

---

### Policy Specification Schema (CRD Design)
**Purpose:** Gives operators a Kubernetes-native way to define and version their Zero Trust baseline.

**CRD structure:**
```yaml
apiVersion: zerotrust.capstone.io/v1alpha1
kind: ZeroTrustPolicy
metadata:
  name: cluster-baseline
spec:
  rbac:
    denyWildcardVerbs: true          # gates RBAC-001 (ClusterRole) and RBAC-004 (Role)
    denyWildcardResources: true      # gates RBAC-002 (ClusterRole) and RBAC-005 (Role)
    denyClusterAdminBinding:         # gates RBAC-003
      excludeServiceAccounts:
        - system:masters
        - kube-system/*
    requireNamespacedRoles: true     # gates RBAC-006
  networkPolicy:
    requireDefaultDenyIngress: true  # gates NP-001
    requireDefaultDenyEgress: false  # gates NP-002
    exemptNamespaces:
      - kube-system
      - monitoring
  remediation:
    mode: auto          # auto | dryrun | manual
    rateLimit: 5        # max auto-remediations per 30-second window
    requireApprovalFor:
      - ClusterAdminBinding
```

**Generated from:** `api/v1alpha1/zerotrustpolicy_types.go` via `make manifests`.

---

### Audit Engine
**Purpose:** The scheduler and coordinator. Runs the reconciliation loop, invokes detectors, and collects ViolationEvents.

**Triggers:** Time-based (`RequeueAfter: 30s`) and event-based (controller-runtime watches on ClusterRole, ClusterRoleBinding, RoleBinding, NetworkPolicy, Namespace — any change enqueues an immediate reconcile for `cluster-baseline`).

**Deduplication:** An in-memory `seenViolations` map keyed by `ViolationKey{ViolationType, ResourceName, Namespace}` tracks known violations. Only new violations flow through the decision engine. Known violations are counted but not re-processed. When a violation disappears from the cluster (after remediation), its key is pruned so re-introduction is counted as fresh.

**Implementation:** `internal/controller/zerotrustpolicy_controller.go`.

---

### RBAC Violation Detector
**Purpose:** Identifies RBAC configurations that violate Zero Trust principles.

**Implemented checks:**
- **RBAC-001**: ClusterRoles with `verbs: ["*"]` (gated by `denyWildcardVerbs`)
- **RBAC-002**: ClusterRoles with `resources: ["*"]` (gated by `denyWildcardResources`)
- **RBAC-003**: ClusterRoleBindings and namespaced RoleBindings to `cluster-admin` for non-whitelisted subjects
- **RBAC-004**: Namespaced Roles with `verbs: ["*"]` (gated by `denyWildcardVerbs`)
- **RBAC-005**: Namespaced Roles with `resources: ["*"]` (gated by `denyWildcardResources`)
- **RBAC-006**: ClusterRoleBindings where non-system subjects are bound to non-system ClusterRoles (gated by `requireNamespacedRoles`)

**Implementation:** `internal/controller/detection.go`.

---

### NetworkPolicy Violation Detector
**Purpose:** Identifies namespaces operating without Zero Trust network controls.

**Implemented checks:**
- **NP-001**: Active namespaces (not in `exemptNamespaces`) that lack a default-deny ingress NetworkPolicy. A valid default-deny policy requires: empty `podSelector`, `Ingress` in `policyTypes` (explicit or implicit), and empty ingress rules.
- **NP-002**: Active namespaces that lack a default-deny egress NetworkPolicy. Requires explicit `Egress` in `policyTypes` and empty egress rules. Detection-only — no autofix.

**Implementation:** `internal/controller/detection.go`.

---

### Remediation Decision Engine
**Purpose:** Takes a ViolationEvent and decides what to do with it.

**Outputs:** One of `AUTO_FIX`, `ESCALATE`, `DRY_RUN_LOG`, or `SKIP`.

**Logic sequence:**
1. `requireApprovalFor` check — if the violation type is listed, always escalate (before mode overrides)
2. Mode override — `manual` forces ESCALATE, `dryrun` converts AUTO_FIX to DRY_RUN_LOG
3. Matrix lookup — `decisionFromMatrix()` returns the default action for violation type + risk level

**Implementation:** `internal/controller/decision.go` — `Decide()` and `decisionFromMatrix()`.

---

### Kubernetes Controller Loop
**Purpose:** Executes remediation actions. The only component that writes to the Kubernetes API.

**Autofix implementations:**
- **NP-001 LOW**: Creates `ztk8s-default-deny-ingress` NetworkPolicy via Server-Side Apply (idempotent)
- **RBAC-001 LOW**: Removes wildcard verbs from ClusterRole via `Update`; skips if `*` is the sole verb in any rule (cannot safely replace without knowing intended access)

**Rate limiting:** `windowRateLimit(limit int) bool` tracks remediations within a 30-second time window. Budget is shared across all reconcile cycles within the same window, including watch-triggered cycles.

**Audit batch write:** All audit entries for a cycle (auto-fixes, escalations, dry-runs, skips) are collected in `pendingAuditEntries` and written in a single `AppendAuditEntries` call at the end of reconcile. This avoids optimistic concurrency conflicts from per-entry writes.

**Implementation:** `internal/controller/remediation.go`, `internal/controller/zerotrustpolicy_controller.go`.

---

### Logging, Audit Trail, and Metrics
**Purpose:** Makes the system observable, defensible, and measurable.

**Violation logging:** Structured JSON to stdout via zerolog. Every violation detected emits one line with: `timestamp`, `violationType`, `resourceName`, `namespace`, `riskLevel`, `violation_detected` message. Schema is stable for downstream SIEM ingestion.

**Audit trail:** Append-only JSON-lines log written to `ztk8s-audit-log` ConfigMap in the `zerotrust-system` namespace. Each key holds up to 900KB before rolling over to a new key (`audit.log`, `audit.log.2`, etc.). Batch-written once per reconcile cycle.

**Status conditions:** After every successful reconcile cycle, an `AuditComplete` condition is written to the `ZeroTrustPolicy` status subresource with a summary message. Visible via `kubectl describe zerotrustpolicy cluster-baseline`.

**Prometheus metrics** exposed at `:8080/metrics` (plain HTTP, not HTTPS):

| Metric | Type | Labels |
|--------|------|--------|
| `ztk8s_violations_total` | Counter | `violation_type`, `namespace`, `risk_level` |
| `ztk8s_remediations_total` | Counter | `violation_type`, `namespace` |
| `ztk8s_escalations_total` | Counter | `violation_type`, `namespace` |
| `ztk8s_cycle_duration_seconds` | Histogram | — |

**Implementation:** `internal/controller/metrics.go`, `internal/controller/violation_log.go`, `internal/controller/auditlog.go`.

---

## Tech Stack

| Concern | Choice | Reason |
|---|---|---|
| Language | Go | Native Kubernetes language, single binary, first-class client libraries |
| Kubernetes client | controller-runtime | Standard for controllers, includes informer cache, reconciler interface |
| CRD generation | Kubebuilder + controller-gen | Industry standard, auto-generates CRD YAML from Go structs |
| Controller pattern | Reconciliation (not admission) | Must catch pre-existing misconfigurations and drift — admission controllers miss these |
| Data storage | In-memory + ConfigMap audit log | No external DB needed; state is rebuilt from cluster on restart |
| Metrics | Prometheus + client_golang | Standard observability stack for Kubernetes |
| Test environment | minikube | Local single-node cluster, fast to reset, sufficient for all scenarios |

---

## Enforcement and Drift Strategy

**Triggers:** Time-based (RequeueAfter: 30s) and event-based (watches on ClusterRole, ClusterRoleBinding, RoleBinding, NetworkPolicy, Namespace). Any change triggers an immediate reconcile.

**Reconciliation:** Every cycle fetches desired state from Policy Store and actual state from Kubernetes API via informer cache, diffs them, produces ViolationEvents, passes new ones to decision engine.

**Avoiding workload disruption:** Exemption list in CRD, dry-run mode, autofix scope limited to additive controls (apply NP, remove verbs). Never auto-deletes roles or bindings. `kube-system` is guarded at both the risk-classifier level (CRITICAL → SKIP) and inside `applyRemediation` as a secondary defense-in-depth check.

**Idempotency:** NP-001 autofix uses Server-Side Apply. RBAC-001 autofix re-fetches and re-checks before patching.

**Rollback:** Pre-remediation state serialized to audit log as JSON before any write.

---

## Failure Mode Analysis

| Failure | Behavior |
|---|---|
| Audit engine crashes mid-cycle | controller-runtime restarts; fresh cycle on restart; gap in logs only; seenViolations cache reset (all violations re-detected as new in first cycle) |
| False positive triggers autofix | Dry-run mode prevents writes; audit log enables manual rollback; exemption list protects sensitive resources; kube-system secondary guard prevents write |
| Kubernetes API temporarily unavailable | controller-runtime uses exponential backoff; informer cache serves reads; no writes attempted until API recovers |
| Runaway remediation burst | Time-window rate limit (default 5/30s) caps blast radius; excess violations escalated rather than auto-fixed |
| Audit ConfigMap full | Key rolls over at 900KB to a new key (`audit.log.2`, etc.); no data loss |
| Status condition write fails | Non-fatal — logged and ignored; audit cycle result is not affected |
