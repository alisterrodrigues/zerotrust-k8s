# ZeroTrust-K8s

A Zero Trust Policy Enforcement and Automated Misconfiguration Remediation System for Kubernetes.

## What This Is

A Kubernetes-native controller that continuously audits RBAC and NetworkPolicy configurations, detects Zero Trust violations, automatically remediates low-risk violations, and escalates high-risk ones for human review.

## Documentation

- [Architecture](docs/architecture.md) — system design, components, event flow
- [Remediation Model](docs/remediation-model.md) — violation types, risk levels, decision matrix
- [Threat Model](docs/threat-model.md) — STRIDE analysis, trust boundaries, limitations
- [Evaluation Plan](docs/evaluation-plan.md) — metrics and test scenarios
- [Roadmap](docs/roadmap.md) — phased deliverables

## Project Structure

```
zerotrust-k8s/
├── docs/                    # All design and planning documents
├── baseline/                # ZeroTrustPolicy CRD YAML definitions
├── audit-engine/            # Audit loop and detector modules
├── remediation-engine/      # Decision engine and autofix logic
├── controller/              # Main controller loop and reconciler
├── crds/                    # Custom Resource Definition schemas
├── manifests/               # Test RBAC and NetworkPolicy YAMLs
│   ├── rbac/
│   ├── networkpolicy/
│   └── test-scenarios/
├── evaluations/             # Test scenario scripts and results
├── dashboard/               # Observability (Phase 3)
└── .cursorrules             # AI coding assistant context
```

## Prerequisites

- Go 1.21+
- kubectl
- minikube
- Kubebuilder CLI
- controller-gen

## Status

Currently in Phase 1 — Baseline + Audit Engine + Violation Detection.
