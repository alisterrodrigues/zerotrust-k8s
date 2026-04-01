#!/usr/bin/env bash
# Scenario 02 — RBAC-001 detection+remediation latency
# Creates a ClusterRole with wildcard verbs, measures time to audit log entry.
# A role with no bindings is LOW risk → AUTO_FIX (wildcard verbs stripped).
# We measure time from role creation to the AUTO_REMEDIATED audit entry.

set -euo pipefail
ROLE="eval-rbac001-$(date +%s)"
echo "==> Creating wildcard ClusterRole $ROLE at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
T1=$(date +%s%N)
kubectl create clusterrole "$ROLE" \
  --verb='*' --resource='pods'
echo "T1_ROLE=$ROLE T1_EPOCH_NS=$T1"
echo "==> Waiting for audit log entry (up to 90s covers 3 full reconcile cycles)..."
for i in $(seq 1 90); do
  # Search all audit log keys (audit.log, audit.log.2, etc.) in case of rollover.
  ENTRY=$(kubectl get configmap ztk8s-audit-log \
    -n zerotrust-system -o json 2>/dev/null \
    | python3 -c "
import sys, json
d = json.load(sys.stdin).get('data', {})
for v in d.values():
    for line in v.splitlines():
        if '$ROLE' in line:
            print(line)
" 2>/dev/null | tail -1)
  if [ -n "$ENTRY" ]; then
    T2=$(date +%s%N)
    LATENCY_MS=$(( (T2 - T1) / 1000000 ))
    echo "==> DETECTED in ${LATENCY_MS}ms"
    echo "RESULT: scenario=RBAC-001 role=$ROLE latency_ms=$LATENCY_MS"
    kubectl delete clusterrole "$ROLE" --ignore-not-found
    exit 0
  fi
  sleep 1
done
echo "ERROR: Audit log entry not found within 90 seconds"
kubectl delete clusterrole "$ROLE" --ignore-not-found
exit 1
