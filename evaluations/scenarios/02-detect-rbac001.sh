#!/usr/bin/env bash
# Scenario 02 — RBAC-001 detection latency
# Creates a ClusterRole with wildcard verbs, measures detection time.
# This is HIGH risk so it will be ESCALATED not auto-remediated.
# We measure time to audit log entry, not remediation.

set -euo pipefail
ROLE="eval-rbac001-$(date +%s)"
echo "==> Creating wildcard ClusterRole $ROLE at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
T1=$(date +%s%N)
kubectl create clusterrole "$ROLE" \
  --verb='*' --resource='pods'
echo "T1_ROLE=$ROLE T1_EPOCH_NS=$T1"
echo "==> Waiting for audit log entry..."
for i in $(seq 1 60); do
  ENTRY=$(kubectl get configmap ztk8s-audit-log \
    -n zerotrust-system -o jsonpath='{.data.audit\.log}' 2>/dev/null \
    | grep "$ROLE" | tail -1)
  if [ -n "$ENTRY" ]; then
    T2=$(date +%s%N)
    LATENCY_MS=$(( (T2 - T1) / 1000000 ))
    echo "==> DETECTED in ${LATENCY_MS}ms"
    echo "RESULT: scenario=RBAC-001 role=$ROLE latency_ms=$LATENCY_MS"
    kubectl delete clusterrole "$ROLE"
    exit 0
  fi
  sleep 1
done
echo "ERROR: Audit log entry not found within 60 seconds"
kubectl delete clusterrole "$ROLE" --ignore-not-found
exit 1
