# Remediation Model — Zero Trust K8s

## Violation Type Registry

| ID       | Category      | Description                                                                 | Scope          |
|----------|---------------|-----------------------------------------------------------------------------|----------------|
| RBAC-001 | RBAC          | Wildcard verb (`*`) in ClusterRole                                          | ClusterRole    |
| RBAC-002 | RBAC          | Wildcard resource (`*`) in ClusterRole                                      | ClusterRole    |
| RBAC-003 | RBAC          | cluster-admin bound to non-whitelisted subject (ClusterRoleBinding or RoleBinding) | Cluster-wide |
| RBAC-004 | RBAC          | Wildcard verb (`*`) in namespaced Role                                      | Namespaced     |
| RBAC-005 | RBAC          | Wildcard resource (`*`) in namespaced Role                                  | Namespaced     |
| RBAC-006 | RBAC          | Non-system ClusterRoleBinding candidate for namespace-scoping (RequireNamespacedRoles) | ClusterRoleBinding |
| NP-001   | NetworkPolicy | Namespace missing a default-deny ingress NetworkPolicy                      | Namespace      |
| NP-002   | NetworkPolicy | Namespace missing a default-deny egress NetworkPolicy                       | Namespace      |

> **Note:** RBAC-006 is detection-only. NP-002 is detection-only. Neither has an autofix path — see Decision Matrix below.

---

## Risk Classification Criteria

**LOW** — violation affects a single namespace or unbound role, no evidence of active exploitation, remediation action is purely additive (adds a control), rollback is trivial.

**HIGH** — violation grants cluster-wide access, involves a subject currently bound to running workloads, or has active bindings. Remediation requires deletion or modification of existing permissions.

**CRITICAL** — violation involves a direct path to cluster-admin escalation, affects `kube-system` or system-prefixed roles, or the remediation action could break running system components.

---

## Risk Level per Detector

| Violation | Context                                      | Risk Level |
|-----------|----------------------------------------------|------------|
| RBAC-001  | ClusterRole name has `system:` prefix        | CRITICAL   |
| RBAC-001  | Has active ClusterRoleBinding or RoleBinding | HIGH       |
| RBAC-001  | No bindings, non-system role                 | LOW        |
| RBAC-002  | Any context                                  | HIGH       |
| RBAC-003  | Subject kind is `User`                       | CRITICAL   |
| RBAC-003  | Subject kind is `ServiceAccount` or `Group`  | HIGH       |
| RBAC-004  | Any context                                  | HIGH       |
| RBAC-005  | Any context                                  | HIGH       |
| RBAC-006  | Any context                                  | LOW        |
| NP-001    | `kube-system` namespace                      | CRITICAL   |
| NP-001    | Namespace has Running or Pending pods        | HIGH       |
| NP-001    | Namespace is empty                           | LOW        |
| NP-002    | `kube-system` namespace                      | CRITICAL   |
| NP-002    | Any other namespace                          | HIGH       |

---

## Formal Decision Matrix

| Violation | Risk     | Context                                   | Remediation Action                          |
|-----------|----------|-------------------------------------------|---------------------------------------------|
| NP-001    | LOW      | Non-system, empty namespace               | AUTO: Apply `ztk8s-default-deny-ingress` NP |
| NP-001    | HIGH     | Has running pods                          | ESCALATE: Recommend safe NP with allow-rules|
| NP-001    | CRITICAL | `kube-system` / exempt namespace          | SKIP: Log only                              |
| NP-002    | HIGH     | Any non-system namespace                  | ESCALATE: Recommend egress policy           |
| NP-002    | CRITICAL | `kube-system`                             | ESCALATE: Alert immediately                 |
| RBAC-001  | LOW      | Non-system, no active bindings            | AUTO: Remove wildcard verbs from ClusterRole|
| RBAC-001  | HIGH     | Active bindings exist                     | ESCALATE: Recommend patch                   |
| RBAC-001  | CRITICAL | System-prefixed ClusterRole               | ESCALATE: Alert immediately                 |
| RBAC-002  | HIGH     | Any context                               | ESCALATE: Recommend explicit resource scope |
| RBAC-003  | HIGH     | Non-User subject, non-whitelisted         | ESCALATE: Recommend revoke                  |
| RBAC-003  | CRITICAL | User subject, non-whitelisted             | ESCALATE: Alert immediately                 |
| RBAC-004  | HIGH     | Any context                               | ESCALATE: Recommend patch                   |
| RBAC-005  | HIGH     | Any context                               | ESCALATE: Recommend patch                   |
| RBAC-006  | LOW      | Non-system CRB candidate for scoping      | ESCALATE: Recommend namespace-scoped Role   |
| (default) | Any      | Unmapped violation type                   | ESCALATE: Safety fallback                   |

> **Decision engine location:** `internal/controller/decision.go` — `Decide()` and `decisionFromMatrix()`.

---

## Autofix Permitted Actions

The following actions may be executed automatically when risk level is LOW and remediation mode is `auto`:

- **NP-001 LOW**: Apply a `ztk8s-default-deny-ingress` NetworkPolicy to an unprotected empty namespace. Uses Server-Side Apply — idempotent, safe to repeat.
- **RBAC-001 LOW**: Remove wildcard verbs from a non-system ClusterRole that has no active bindings. Uses `Update`. If `*` is the sole verb in a rule (no safe replacement), the autofix is skipped and the violation is left for human review.

The following actions are **never** auto-executed regardless of risk or mode:

- Deleting any Role, ClusterRole, RoleBinding, or ClusterRoleBinding
- Modifying any resource in `kube-system` or the controller's own namespace
- Any action on a resource in the exemption list
- Any action for RBAC-002, RBAC-003, RBAC-004, RBAC-005, RBAC-006, or NP-002 (detection and escalation only)

---

## Mode Overrides

The `spec.remediation.mode` field overrides the matrix action:

| Mode     | Effect                                                              |
|----------|---------------------------------------------------------------------|
| `auto`   | Matrix is applied as-is (default)                                   |
| `dryrun` | AUTO_FIX decisions become DRY_RUN_LOG — no API writes              |
| `manual` | All decisions become ESCALATE — no API writes                       |

`spec.remediation.requireApprovalFor` lists violation types that always escalate regardless of mode or risk. Evaluated before mode overrides. Example: `requireApprovalFor: ["ClusterAdminBinding"]` forces RBAC-003 to always escalate.

---

## Rate Limiting

`spec.remediation.rateLimit` (default: 5) sets the maximum number of auto-remediations allowed within a 30-second time window. The window is shared across all reconcile cycles that fire within a 30-second period, including event-driven watch triggers. Violations that exceed the budget in the current window are escalated rather than auto-fixed.

The rate limit counter resets automatically when a new 30-second window begins. This is enforced by the `windowRateLimit()` method on the reconciler (`internal/controller/zerotrustpolicy_controller.go`).

---

## Escalation Format

Every escalation and auto-remediation written to the audit log (`ztk8s-audit-log` ConfigMap in `zerotrust-system`) is a JSON line conforming to the `AuditEntry` struct (`internal/controller/auditlog.go`):

```json
{
  "EntryID": "aud-20260416150405.000000000-rbac-001-developer-role",
  "ViolationType": "RBAC-001",
  "RiskLevel": "HIGH",
  "ResourceName": "developer-role",
  "Namespace": "",
  "Action": "ESCALATED",
  "Reason": "RBAC-001 HIGH: active bindings exist, escalate",
  "PreRemediationSnapshot": "{...full resource JSON...}",
  "SuggestedAction": "Review impacted subjects and patch role verbs safely.",
  "Timestamp": "2026-04-16T15:04:05.000000000Z"
}
```

Action values: `AUTO_REMEDIATED`, `ESCALATED`, `DRY_RUN`, `SKIPPED`.

---

## Safety Mechanisms

**Dry-run mode** (`remediation.mode: dryrun`): All AUTO_FIX decisions become DRY_RUN_LOG — the intended action is recorded in the audit log with no API writes.

**Rate limiting** (`remediation.rateLimit: 5`): Maximum N auto-remediations per 30-second time window. Enforced by a time-window counter, not a per-cycle counter, so event-driven watch bursts are correctly throttled.

**Approval gates** (`remediation.requireApprovalFor`): Named violation types that always escalate regardless of risk level or mode. Evaluated before mode overrides.

**kube-system guard**: A secondary defense-in-depth check in `applyRemediation` prevents any write to `kube-system` even if the decision matrix is bypassed by a future code path.

**Pre-remediation snapshot**: Full JSON of the target resource written to the audit ConfigMap before any mutation. Serves as a rollback record for human recovery.

**Exemption list** (`networkPolicy.exemptNamespaces`): Named namespaces never flagged by NP-001 or NP-002 detectors.

**Idempotent autofixes**: NP-001 uses Server-Side Apply (re-apply is a no-op). RBAC-001 re-checks the role state before patching and returns a no-op if already clean.
