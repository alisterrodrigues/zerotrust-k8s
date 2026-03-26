# Remediation Model — Zero Trust K8s

## Violation Type Registry

| ID       | Category      | Description                                               |
|----------|---------------|-----------------------------------------------------------|
| RBAC-001 | RBAC          | Wildcard verb in ClusterRole or Role                      |
| RBAC-002 | RBAC          | Wildcard resource in ClusterRole or Role                  |
| RBAC-003 | RBAC          | cluster-admin bound to non-whitelisted subject            |
| RBAC-004 | RBAC          | Service account with cross-namespace secret access        |
| RBAC-005 | RBAC          | Role granting access to all secrets cluster-wide          |
| NP-001   | NetworkPolicy | Namespace has no NetworkPolicy (default allow-all)        |
| NP-002   | NetworkPolicy | NetworkPolicy with empty podSelector and no ingress rules |
| NP-003   | NetworkPolicy | Pod not matched by any NetworkPolicy selector             |

---

## Risk Classification Criteria

**LOW** — violation affects a single namespace, no evidence of active exploitation, remediation action is purely additive (adds a control), rollback is trivial.

**HIGH** — violation grants cluster-wide access, affects system namespaces, involves a subject currently bound to running workloads, or remediation requires deletion or modification of existing permissions.

**CRITICAL** — violation involves a direct path to cluster-admin escalation, affects kube-system or the controller's own namespace, or the remediation action could break running system components.

---

## Formal Decision Matrix

| Violation | Risk     | Context                        | Remediation Action              |
|-----------|----------|--------------------------------|---------------------------------|
| NP-001    | LOW      | Non-system namespace           | AUTO: Apply default-deny NP     |
| NP-001    | HIGH     | Has running pods               | ESCALATE: Recommend NP          |
| NP-001    | CRITICAL | kube-system / exempted NS      | SKIP: Log only                  |
| NP-002    | LOW      | No pods matched                | AUTO: Patch NP selector         |
| NP-002    | HIGH     | Active pods matched            | ESCALATE: Recommend patch       |
| NP-003    | HIGH     | Any context                    | ESCALATE: Recommend NP update   |
| RBAC-001  | LOW      | Non-system, no active bindings | AUTO: Remove wildcard verb      |
| RBAC-001  | HIGH     | Active bindings exist          | ESCALATE: Recommend patch       |
| RBAC-001  | CRITICAL | System namespace role          | ESCALATE: Alert immediately     |
| RBAC-002  | HIGH     | Any context                    | ESCALATE: Recommend scope       |
| RBAC-003  | HIGH     | Any non-whitelisted subject    | ESCALATE: Recommend revoke      |
| RBAC-003  | CRITICAL | External / unknown subject     | ESCALATE: Alert immediately     |
| RBAC-004  | HIGH     | Any context                    | ESCALATE: Recommend scope       |
| RBAC-005  | HIGH     | Any context                    | ESCALATE: Recommend scope       |

---

## Autofix Permitted Actions

The following actions may be executed automatically when risk level is LOW and remediation mode is `auto`:

- Apply a default-deny ingress NetworkPolicy to an unprotected namespace
- Patch a NetworkPolicy with an empty podSelector to add a restrictive selector
- Remove a wildcard verb from a non-system Role with no active bindings

The following actions are **never** auto-executed regardless of risk or mode:

- Deleting any Role, ClusterRole, RoleBinding, or ClusterRoleBinding
- Modifying any resource in kube-system or the controller's own namespace
- Any action on a resource in the exemption list

---

## Escalation Format

Every escalation written to the audit log includes:

```json
{
  "escalationId": "esc-20240301-rbac001-default",
  "violationType": "RBAC-001",
  "riskLevel": "HIGH",
  "resource": {
    "kind": "ClusterRole",
    "name": "developer-role",
    "namespace": "default"
  },
  "detectedAt": "2024-03-01T14:22:00Z",
  "reason": "Active RoleBindings exist referencing this role. Auto-remediation skipped.",
  "suggestedAction": "Remove wildcard verbs from rules[0]. Replace with explicit verb list.",
  "preRemediationSnapshot": "{...full resource JSON...}"
}
```

---

## Safety Mechanisms

**Dry-run mode** (`remediation.mode: dryrun`): All remediation actions log their intended effect with no API writes. Enabled by default on first install.

**Rate limiting** (`remediation.rateLimit: 5`): Maximum N auto-remediations per reconcile cycle. Configurable in CRD.

**Circuit breaker**: If more than 2× the rate limit fires in a single cycle, auto-remediation is paused for the remainder of that cycle and everything is escalated.

**Approval gates** (`remediation.requireApprovalFor`): Named violation types that require explicit operator opt-in before auto-remediation is permitted. RBAC-003 and RBAC-005 default to this.

**Pre-remediation snapshot**: Full JSON of the target resource written to audit log ConfigMap before any mutation.

**Exemption list** (`networkPolicy.exemptNamespaces`, future `rbac.exemptRoles`): Named resources that are never auto-remediated.
