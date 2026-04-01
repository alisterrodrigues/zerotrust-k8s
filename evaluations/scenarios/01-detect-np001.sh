#!/usr/bin/env bash
# Scenario 01 — NP-001 detection latency
# Creates a namespace with no NetworkPolicy and measures how long
# until the controller detects it and auto-remediates it.
# Usage: ./01-detect-np001.sh
# Requires: controller running via make run in another terminal

set -euo pipefail
NS="eval-np001-$(date +%s)"
echo "==> Creating namespace $NS at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
T1=$(date +%s%N)
kubectl create namespace "$NS"
echo "T1_NS=$NS T1_EPOCH_NS=$T1"
echo "==> Waiting for ztk8s-default-deny-ingress to appear..."
for i in $(seq 1 60); do
  if kubectl get networkpolicy ztk8s-default-deny-ingress \
     -n "$NS" &>/dev/null 2>&1; then
    T2=$(date +%s%N)
    LATENCY_MS=$(( (T2 - T1) / 1000000 ))
    echo "==> DETECTED AND REMEDIATED in ${LATENCY_MS}ms"
    echo "RESULT: scenario=NP-001 namespace=$NS latency_ms=$LATENCY_MS"
    kubectl delete namespace "$NS"
    exit 0
  fi
  sleep 1
done
echo "ERROR: NetworkPolicy not applied within 60 seconds"
kubectl delete namespace "$NS"
exit 1
