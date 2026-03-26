# Architecture — Zero Trust Policy Enforcement and Automated Misconfiguration Remediation System for Kubernetes

## System Vision

### What We Are Building
A Kubernetes-native security controller (ZeroTrust-K8s) that runs a continuous loop: watches RBAC and NetworkPolicy configurations, compares them against a formally defined Zero Trust baseline, and when it finds a gap either fixes it automatically or escalates it for human review with a structured recommendation.

The system runs inside your Kubernetes cluster as a controller — a long-running process that reconciles desired state (your Zero Trust baseline) with actual state (what's currently configured in the cluster). It is not a one-time scanner. It runs continuously, catching drift as it happens.

### What Makes It Different from OPA/Kyverno
OPA and Kyverno are admission controllers — they sit at the door and decide whether to let new resources in. They are preventive. They do nothing about violations that already exist, configurations that drifted after admission, or legacy misconfigurations present before the tool was installed.

This system is corrective and continuous. It doesn't just block — it hunts, classifies, and fixes. The remediation decision engine is the intellectual contribution that neither OPA nor Kyverno has.

### MVP Definition
The MVP is a system that can:
- Load a Zero Trust baseline from a YAML-defined CRD
- Scan all ClusterRoles, RoleBindings, and NetworkPolicies in a cluster
- Detect three violation types: wildcard RBAC permissions, cluster-admin bindings to non-system accounts, and namespaces missing a default-deny NetworkPolicy
- Classify each violation as low or high risk
- Auto-apply a default-deny NetworkPolicy to unprotected namespaces
- Log all violations and actions to stdout in structured JSON
- Expose a `/metrics` endpoint with violation counts

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
│  Human Reviewer      │◀─── Escalation alerts (audit log / future webhook)
└──────────────────────┘
```

### Control Plane vs Data Plane
**Control plane** — the controller, the baseline CRD, the decision engine. This is where policy lives and decisions are made.

**Data plane** — the actual RBAC objects, NetworkPolicies, and running workloads. The controller reads and modifies these but never becomes them.

### End-to-End Event Flow
```
1.  Operator applies ZeroTrustPolicy CRD to cluster
2.  Baseline Loader reads CRD, populates Policy Store in memory
3.  Audit Engine starts reconciliation loop (every 30s by default)
4.  RBAC Detector queries Kubernetes API for all ClusterRoles,
    RoleBindings, Roles
5.  NetworkPolicy Detector queries all namespaces and their
    NetworkPolicies
6.  Each result is compared against Policy Store rules
7.  Violations are emitted as typed ViolationEvent structs
8.  Remediation Decision Engine receives each ViolationEvent
9.  Risk classifier assigns LOW / HIGH based on decision matrix
10. LOW risk → AutoRemediate() called → Kubernetes API write
11. HIGH risk → Escalation record written to audit log + alert
12. All actions recorded in structured audit trail
13. Metrics counters updated
14. Loop sleeps, then repeats from step 3
```

---

## Core Components

### Zero Trust Baseline Model
**Purpose:** Defines what a compliant cluster looks like. The source of truth — the formal specification of Zero Trust for Kubernetes.

**Inputs:** A `ZeroTrustPolicy` CRD applied by the operator.

**Outputs:** An in-memory policy object that the audit engine queries.

**Internal logic:** Encodes rules such as "no ClusterRole may contain wildcard verbs," "no service account outside kube-system may hold cluster-admin," "every namespace must have a default-deny-ingress NetworkPolicy." Each rule has an ID, description, risk level, and remediation action.

**Implementation:** A Go struct hierarchy that mirrors the CRD schema, loaded at startup and reloaded on CRD update events.

---

### Policy Specification Schema (CRD Design)
**Purpose:** Gives operators a Kubernetes-native way to define and version their Zero Trust baseline without touching the controller code.

**Inputs:** YAML applied with `kubectl apply`.

**Outputs:** A structured object the controller can watch and react to.

**CRD structure:**
```yaml
apiVersion: zerotrust.capstone.io/v1alpha1
kind: ZeroTrustPolicy
metadata:
  name: cluster-baseline
spec:
  rbac:
    denyWildcardVerbs: true
    denyClusterAdminBinding:
      excludeServiceAccounts:
        - system:masters
        - kube-system/*
    requireNamespacedRoles: true
  networkPolicy:
    requireDefaultDenyIngress: true
    requireDefaultDenyEgress: false
    exemptNamespaces:
      - kube-system
      - monitoring
  remediation:
    mode: auto          # auto | dryrun | manual
    rateLimit: 5        # max remediations per minute
    requireApprovalFor:
      - ClusterAdminBinding
```

**Implementation:** Define the CRD in `crds/zerotrust-policy.yaml`, generate Go types using `controller-gen`.

---

### Audit Engine
**Purpose:** The scheduler and coordinator. Runs the reconciliation loop, invokes detectors, and collects ViolationEvents.

**Inputs:** Policy Store (in-memory baseline), Kubernetes API (live cluster state).

**Outputs:** A slice of `ViolationEvent` objects passed to the Remediation Decision Engine.

**Internal logic:** Runs on a ticker (default 30 seconds). On each tick it calls each detector module, aggregates results, deduplicates violations already acted on in the current cycle, and forwards the list downstream.

**Implementation:** A Go goroutine with a `time.Ticker`. Uses `controller-runtime`'s reconciler interface.

---

### RBAC Violation Detector
**Purpose:** Identifies RBAC configurations that violate Zero Trust principles.

**Inputs:** Live list of ClusterRoles, Roles, ClusterRoleBindings, RoleBindings from Kubernetes API. Policy Store rules.

**Outputs:** Typed `RBACViolationEvent` structs.

**Internal logic checks for:**
- Any ClusterRole or Role containing `verbs: ["*"]` or `resources: ["*"]`
- Any ClusterRoleBinding that binds `cluster-admin` to a non-whitelisted subject
- Service accounts with roles that grant cross-namespace access
- Roles that grant access to secrets cluster-wide

Each finding becomes a ViolationEvent with fields: violationType, resourceName, resourceNamespace, riskLevel, detectedAt, suggestedRemediation.

**Implementation:** Go functions that iterate over API objects and apply rule predicates.

---

### NetworkPolicy Violation Detector
**Purpose:** Identifies namespaces and pods operating without Zero Trust network controls.

**Inputs:** Live list of all namespaces and NetworkPolicies. Policy Store rules.

**Outputs:** Typed `NetworkPolicyViolationEvent` structs.

**Internal logic checks for:**
- Namespaces with no NetworkPolicy (default allow-all)
- Namespaces with NetworkPolicies that contain empty pod selectors and no ingress rules
- Pods with labels that don't match any existing NetworkPolicy selector

**Implementation:** Iterate, compare, emit. The namespace-with-no-policy check is the most important and simplest to implement first.

---

### Remediation Decision Engine
**Purpose:** The brain of the system. Takes a ViolationEvent and decides what to do with it.

**Inputs:** ViolationEvent with type, risk context, and resource metadata.

**Outputs:** A `RemediationAction` (AutoFix, Escalate, DryRunLog, Skip).

**Internal logic:** Two-stage process. First, risk classification — map the violation type and context to LOW/HIGH/CRITICAL using the decision matrix. Second, action selection — based on risk level and the policy's remediation mode, select the appropriate action.

Safety check before any autofix: verify the target resource still exists, verify the proposed change is idempotent, verify the rate limit has not been exceeded.

**Implementation:** A Go function `Decide(v ViolationEvent, policy Policy) RemediationAction` with a decision table implemented as a switch/case structure. Deliberately readable and auditable.

---

### Kubernetes Controller Loop
**Purpose:** Executes remediation actions. The only component that writes to the Kubernetes API.

**Inputs:** `RemediationAction` structs.

**Outputs:** Kubernetes API mutations (creates, patches). Audit log entries.

**Internal logic:**
- AutoFix NetworkPolicy: Generate a default-deny NetworkPolicy manifest and apply via API
- AutoFix RBAC: Remove the offending rule from the Role/ClusterRole via patch
- Escalate: Write a structured escalation record to the audit log

**Rollback:** Before any autofix, serialize the current state of the target resource to the audit log. This is your rollback record.

**Implementation:** `controller-runtime` reconciler. Each remediation action is its own reconcile call so failures are isolated.

---

### Logging, Audit Trail, and Metrics
**Purpose:** Makes the system observable, defensible, and measurable.

**Logging:** Structured JSON to stdout. Every violation detected, every action taken, every escalation. Fields: timestamp, component, violationType, resourceName, action, outcome, durationMs.

**Audit trail:** Append-only log of all remediation actions written to a ConfigMap in the controller's namespace.

**Metrics (Prometheus) exposed at `:8080/metrics`:**
- `ztk8s_violations_detected_total` (labels: type, namespace, risk_level)
- `ztk8s_remediations_applied_total` (labels: type, namespace)
- `ztk8s_escalations_total` (labels: type, namespace)
- `ztk8s_audit_cycle_duration_seconds`
- `ztk8s_false_positives_total`

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

**Triggers:** Time-based (reconciliation loop every 30s) and event-based (controller-runtime watch on ClusterRole, ClusterRoleBinding, NetworkPolicy — any change triggers immediate reconcile).

**Reconciliation:** Every cycle fetches desired state from Policy Store and actual state from Kubernetes API via informer cache, diffs them, produces ViolationEvents, passes to decision engine.

**Avoiding workload disruption:** Exemption list in CRD, dry-run mode, and autofix scope limited to additive controls only. Never auto-delete roles or bindings.

**Idempotency:** Every remediation action is safe to apply multiple times. Conflicts are handled gracefully as no-ops.

**Rollback:** Pre-remediation state serialized to audit log as JSON before any write. Manual restore from audit log. 

---

## Failure Mode Analysis

| Failure | Behavior |
|---|---|
| Audit engine crashes mid-cycle | controller-runtime restarts via liveness probe; fresh cycle on restart; gap in logs only |
| False positive triggers autofix | Dry-run mode prevents it in validation phase; audit log enables manual rollback; exemption list protects sensitive resources |
| Kubernetes API temporarily unavailable | controller-runtime uses exponential backoff; informer cache serves reads; no writes attempted until API recovers |
| Runaway remediation loop | Rate limit (5/cycle default) caps blast radius; circuit breaker pauses auto-remediation if M remediations fire in one cycle |
