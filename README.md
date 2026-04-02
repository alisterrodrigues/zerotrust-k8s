# zerotrust-k8s

A Zero Trust Policy Enforcement and Automated Misconfiguration Remediation System for Kubernetes.

Capstone project — Pace University, Seidenberg School of CSIS.  
Team: Alister Rodrigues, Pranav Karelia, Siddhant Patel.

## What This Is

A Kubernetes-native operator that continuously audits RBAC and NetworkPolicy configurations against a formally defined Zero Trust baseline. The system detects violations, automatically remediates low-risk misconfigurations (NP-001, RBAC-001 LOW), escalates high-risk ones for human review, and exposes Prometheus metrics for observability.

## Status

**Phase 3 complete.** All three implementation phases are done:
- Phase 1: ZeroTrustPolicy CRD, four detectors (RBAC-001/002/003, NP-001), structured JSON logging
- Phase 2: Remediation engine, NP-001 + RBAC-001 autofixes, audit log, rate limiting, dry-run mode
- Phase 3: Prometheus metrics, violation deduplication, formal evaluation (all 5 metrics measured)

See [`evaluations/results.md`](evaluations/results.md) for full evaluation results.

## Documentation

- [Architecture](docs/architecture.md) — system design, components, event flow
- [Remediation Model](docs/remediation-model.md) — violation types, risk levels, decision matrix
- [Threat Model](docs/threat-model.md) — STRIDE analysis, trust boundaries, limitations
- [Evaluation Plan](docs/evaluation-plan.md) — metrics and test scenarios
- [Evaluation Results](evaluations/results.md) — measured results for all 5 metrics
- [Roadmap](docs/roadmap.md) — phased deliverables

## Project Structure

```
zerotrust-k8s/
├── api/v1alpha1/              # ZeroTrustPolicy CRD Go types
├── cmd/main.go                # Operator entry point
├── config/
│   ├── crd/bases/             # Generated CRD YAML (do not edit)
│   ├── rbac/                  # Generated RBAC (do not edit)
│   └── samples/               # cluster-baseline ZeroTrustPolicy CR
├── docs/                      # Architecture, threat model, remediation model
├── evaluations/
│   ├── scenarios/             # Evaluation scenario shell scripts
│   └── results.md             # Formal evaluation results
├── internal/controller/
│   ├── auditlog.go            # ConfigMap audit log writer
│   ├── decision.go            # Remediation decision engine
│   ├── detection.go           # RBAC-001/002/003 and NP-001 detectors
│   ├── metrics.go             # Prometheus counters and histograms
│   ├── remediation.go         # NP-001 and RBAC-001 autofixes
│   ├── types.go               # ViolationEvent, ViolationKey types
│   ├── violation_log.go       # Structured zerolog violation logging
│   └── zerotrustpolicy_controller.go  # Main reconcile loop
├── setup.sh                   # Session setup script (run before make run)
├── Makefile                   # Build, test, install targets
└── .cursorrules               # AI coding assistant context
```

## Prerequisites

- Go 1.21+
- kubectl
- minikube
- Docker Desktop (required for minikube Docker driver on Mac M3)
- Kubebuilder CLI v4
- controller-gen

## Running the Project

**Step 1 — Start minikube (once per machine session):**
```bash
minikube start --driver=docker
```

**Step 2 — Session setup and start controller:**
```bash
git pull
./setup.sh
make run
```

`setup.sh` creates required namespaces, installs CRDs, applies the `cluster-baseline` CR, and resets the audit log ConfigMap. `make run` starts the controller. Wait for:
```
reconcile cycle summary ... new_violations: 0 known_violations: 9
```
That indicates steady state — all pre-existing violations have been detected and handled.

**Step 3 — Run evaluation scenarios (in a second terminal):**
```bash
cd evaluations/scenarios
./01-detect-np001.sh        # NP-001 detection + remediation latency
./02-detect-rbac001.sh      # RBAC-001 detection + remediation latency
./03-false-positive.sh      # False positive rate
./04-rate-limit.sh          # Rate limit enforcement
./05-availability.sh        # Workload availability impact
```

**View Prometheus metrics:**
```bash
curl http://localhost:8080/metrics | grep ztk8s
```

**Inspect audit log:**
```bash
kubectl get configmap ztk8s-audit-log -n zerotrust-system -o jsonpath='{.data.audit\.log}' | python3 -m json.tool --no-ensure-ascii 2>/dev/null | head -100
```
