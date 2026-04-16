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

## OPEN — Round 3 Verification Findings (2026-04-16)

### V-1 — RBAC-001 wildcard-only skip produces no audit entry and no metric
**File:** `internal/controller/remediation.go`
**Status:** 🔴 OPEN
**Description:** When a ClusterRole has `*` as its sole verb in a rule (no other verbs),
`removeWildcardVerbsForRBAC001Low` detects it cannot safely remove the wildcard, logs
internally, and returns `(nil, nil)`. The controller receives nil, writes no audit entry,
increments no metric, and adds the violation to `seenViolations` as if it was handled.
The rate limit window counter is still consumed by a no-op. `ztk8s_skipped_total` is never
incremented. Scenario 02 and Test B both fail because of this — the scenario polls for an
audit entry that never arrives.
**Secondary effect:** 16 stale `eval-rbac001-*` ClusterRoles accumulated in the cluster
across sessions because the scenario's cleanup only runs on success.
**Fix:** In the `!safeToFix` branch, return an `AuditEntry` with `Action: "SKIPPED"` and
`Reason: "wildcard-only verb rule — no safe replacement without inventing verbs"` instead
of `(nil, nil)`. This routes through the normal audit/metric pipeline. Also move the
`windowRateLimit` increment to only happen when `remAuditEntry != nil` (actual write
occurred) — the token should not be consumed by a no-op.

---

### V-2 — Status condition update conflicts under event-driven bursts (~5% of cycles)
**File:** `internal/controller/zerotrustpolicy_controller.go`
**Status:** 🔴 OPEN
**Description:** `r.Status().Update()` uses the `policy` object loaded at the start of
`Reconcile()`. Under event-driven bursts (multiple rapid reconcile cycles triggered by
watches), all in-flight reconciles have stale `resourceVersion` by the time they reach
the status update. ~5% of cycles log `"the object has been modified"`. The core audit,
remediation, and metrics logic completes before this error, so it is non-blocking, but
the `AuditComplete` condition may lag one cycle.
**Fix:** Immediately before calling `r.Status().Update()`, re-fetch the policy object with
`r.Get(ctx, key, &policy)` to refresh `resourceVersion`. This is the standard
controller-runtime pattern documented in AGENTS.md.

---

### V-3 — Audit log append does not check post-append size before writing
**File:** `internal/controller/auditlog.go`
**Status:** 🟡 WARN
**Description:** `currentAuditConfigMapName()` checks the current size of the active
ConfigMap and returns a new name if it is >= 850KB. However `AppendAuditEntries` does not
re-check whether the pending append will push the active object over the threshold. A large
batch of audit entries arriving when the ConfigMap is at 840KB can push it to 890KB+,
overshooting the intended 850KB cap. In practice this only matters at very high audit
volumes but it is a real gap in the rotation guarantee.
**Fix:** In `AppendAuditEntries`, after computing the combined size of all pending lines,
check if `currentSize + pendingSize >= auditLogMaxObjectBytes`. If so, create a new
ConfigMap object for this batch rather than appending to the current one.

---

### V-4 — config/manager/manager.yaml missing NAMESPACE downward API injection (Layer 2)
**File:** `config/manager/manager.yaml`
**Status:** 🟡 WARN (Layer 2 — not blocking for make run)
**Description:** `cmd/main.go` reads the `NAMESPACE` env var and calls `SetAuditNamespace()`
to configure the audit log ConfigMap namespace at runtime. However `config/manager/manager.yaml`
does not inject this env var via the Kubernetes downward API. In a `make deploy` deployment,
the controller runs in `zerotrust-k8s-system` (set by kustomization.yaml) but the audit
namespace falls back to the hardcoded `zerotrust-system` default. Result: audit log writes
fail silently in any deployed (non-make-run) environment.
**Fix:** Add to the manager container spec in `config/manager/manager.yaml`:
```yaml
env:
- name: NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
```

---

## OPEN — Previously identified, deferred to Layer 2

### L2-1 — Leader election disabled; multi-replica unsafe
**File:** `cmd/main.go`, `internal/controller/zerotrustpolicy_controller.go`
**Status:** 🟡 WARN (Layer 2)
**Description:** `enableLeaderElection: false` is the default. The reconciler struct holds
mutable state (`seenViolations`, `rateLimitWindowStart`, `rateLimitWindowCount`) with no
mutex protection. Running multiple replicas causes concurrent map writes and race conditions
on these fields. Safe for single-replica deployment only.

### L2-2 — logViolation() fires at steady state (noise in SIEM pipelines)
**File:** `internal/controller/detection.go`
**Status:** 🟡 WARN (Layer 2)
**Description:** `logViolation()` is called inside detectors on every scan pass regardless
of deduplication state. At steady state, 12 `violation_detected` JSON lines are printed
to stdout every 30 seconds even when `new_violations: 0`. A downstream SIEM would see
continuous "violation_detected" events for persistent known violations.
**Fix:** Gate `logViolation()` calls on the new/known distinction — only call it for
violations that are not already in `seenViolations`.

### L2-3 — Ctrl+C exits with code 1 (cosmetic)
**File:** `cmd/main.go`
**Status:** 🟡 WARN (Layer 2)
**Description:** SIGINT causes graceful shutdown which returns a non-nil error through the
manager chain. `os.Exit(1)` is called on any non-nil error from `mgr.Start()`. In a deployed
environment this is handled by the container runtime correctly, but locally it looks like a
crash.
**Fix:** Check if the error is `context.Canceled` and exit 0 for that case.

---

## FIXED

*(Items move here once confirmed in the repo with date)*

- FIXED 2026-04-01 — ConfigMap optimistic concurrency conflict: batched AppendAuditEntries
- FIXED 2026-04-01 — 02-detect-rbac001.sh timeout extended to 90s
- FIXED 2026-04-02 — setup.sh auto-deletes audit log ConfigMap on startup
- FIXED 2026-04-02 — README updated; .gitignore updated
- FIXED 2026-04-09 — C-1 through C-4, H-1 through H-5, M-1 through M-3, NF-1 through NF-8
  (see git log for details)
- FIXED 2026-04-16 (Round 1) — Audit log verbosity, rate limit regression, M-4, L-2, L-3,
  L-4, NF-7 (see git log for details)
- FIXED 2026-04-16 (Round 2) — A through N (see git log for details)
- FIXED 2026-04-16 (Round 3 prep) — setup.sh now cleans stale eval-rbac001-* ClusterRoles
  and all numbered audit ConfigMaps on session reset
- FIXED 2026-04-16 — zz_generated.deepcopy.go and CRD YAML regenerated to include
  DenyWildcardResources field (was missing since M-4 added the Go type)
