# Threat Model — Zero Trust K8s

## Attacker Personas

### Persona 1: Misconfigured Insider (Highest Probability)
A legitimate cluster user — developer, DevOps engineer — who accidentally grants excessive RBAC permissions, deploys a workload to a namespace without NetworkPolicies, or uses a wildcard role for convenience. This is not malicious intent but is the dominant real-world attack surface. The system's primary value is against this persona.

### Persona 2: Compromised Workload
A running pod that has been exploited via application vulnerability and is attempting lateral movement — querying the Kubernetes API using its service account token, communicating with pods it shouldn't reach. NetworkPolicy enforcement directly limits blast radius. RBAC-004/005 detection limits what a compromised service account can do.

### Persona 3: External Attacker with Initial Foothold
An attacker who has gained code execution in one pod and is attempting privilege escalation via RBAC misconfigurations or network pivoting to reach the API server or other sensitive services. RBAC-001/002/003 detection catches the misconfiguration that enables escalation before or immediately after it appears.

---

## STRIDE Analysis

| Threat | Category | Violation Addressed | Mitigation |
|--------|----------|--------------------|-|
| Compromised service account impersonates another workload | Spoofing | RBAC-004, RBAC-005 | Detect over-privileged service accounts |
| Attacker modifies RBAC roles after gaining API access | Tampering | RBAC-001, RBAC-002 | Detected on next audit cycle / event watch |
| No audit trail of security actions | Repudiation | All | Append-only audit log of all actions |
| Pod reads secrets it shouldn't access | Information Disclosure | RBAC-005 | Detect cluster-wide secret access grants |
| Remediation engine exploited to remove legitimate policies | Denial of Service | System integrity | Rate limiting, circuit breaker, exemption list |
| Wildcard RBAC enables privilege escalation to cluster-admin | Elevation of Privilege | RBAC-001, RBAC-002, RBAC-003 | Detect and remediate/escalate |

---

## Trust Boundaries

```
Boundary 1: External internet → Cluster ingress
            Not managed by this system.

Boundary 2: Namespace → Namespace
            Enforced by NetworkPolicy detection and remediation.
            Violation: NP-001, NP-002, NP-003.

Boundary 3: Pod → Kubernetes API server
            Enforced by RBAC detection.
            Violation: RBAC-001 through RBAC-005.

Boundary 4: Controller namespace → All other namespaces
            The controller itself holds elevated but scoped permissions.
            The controller's own namespace is exempt from auto-remediation
            and must be manually reviewed.
```

---

## System Assumptions

- The Kubernetes API server itself is not compromised
- The controller's own service account and namespace are protected by the operator at install time
- The operator who installs the system is trusted
- etcd is not directly accessible to workloads
- The node operating system and container runtime are not compromised
- The baseline CRD is authored by a trusted operator and reflects intentional policy

---

## Known Limitations

| Limitation | Description |
|---|---|
| No node-level protection | Does not detect or respond to node compromise, kubelet misconfigurations, or host namespace escapes |
| No pod security standards | Does not enforce privileged container restrictions, hostPID, hostNetwork, or seccomp profiles |
| No mTLS enforcement | Service-to-service encryption and mutual authentication are explicitly out of scope |
| Periodic detection gap | Violations that appear and disappear within a single reconcile interval may be missed. Event-based watching mitigates this for most resource types |
| No self-monitoring | The controller does not audit its own namespace or service account for misconfiguration |
| No runtime threat detection | Does not monitor syscalls, network flows, or process activity inside pods |
| No supply chain security | Does not validate container images, signing, or admission from untrusted registries |
