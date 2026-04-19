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
  # Search ALL audit log ConfigMaps (base + any rotation objects ztk8s-audit-log-2, -3, etc.)
  # so the scenario works correctly even after audit log rotation across multiple sessions.
  ENTRY=$(kubectl get configmap -n zerotrust-system -o json \
    $(kubectl get configmap -n zerotrust-system -o name 2>/dev/null \
      | grep 'ztk8s-audit-log' \
      | awk -F/ '{print $2}' \
      | tr '\n' ' ') 2>/dev/null \
    | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
# Handle both single ConfigMap and list responses
if data.get('kind') == 'List':
    items = data.get('items', [])
else:
    items = [data]
for item in items:
    for v in item.get('data', {}).values():
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
