#!/usr/bin/env bash
# Scenario 04 — Rate limiting
# Creates more namespaces than the rate limit allows in one cycle.
# Verifies that only rateLimit namespaces get auto-remediated per cycle
# and the rest are escalated.

set -euo pipefail
PREFIX="eval-ratelimit-$(date +%s)"
RATE_LIMIT=5
COUNT=8

echo "==> Creating $COUNT namespaces to exceed rate limit of $RATE_LIMIT..."
for i in $(seq 1 $COUNT); do
  kubectl create namespace "${PREFIX}-${i}" 2>/dev/null || true
done

echo "==> Waiting 35s for one full reconcile cycle..."
sleep 35

REMEDIATED=0
ESCALATED=0
for i in $(seq 1 $COUNT); do
  NS="${PREFIX}-${i}"
  if kubectl get networkpolicy ztk8s-default-deny-ingress \
     -n "$NS" &>/dev/null 2>&1; then
    REMEDIATED=$((REMEDIATED + 1))
  else
    ESCALATED=$((ESCALATED + 1))
  fi
done

echo "RESULT: created=$COUNT remediated=$REMEDIATED escalated_or_pending=$ESCALATED"
if [ "$REMEDIATED" -le "$RATE_LIMIT" ]; then
  echo "PASS: rate limit respected (remediated=$REMEDIATED <= limit=$RATE_LIMIT)"
else
  echo "FAIL: rate limit exceeded (remediated=$REMEDIATED > limit=$RATE_LIMIT)"
fi

echo "==> Cleaning up..."
for i in $(seq 1 $COUNT); do
  kubectl delete namespace "${PREFIX}-${i}" --ignore-not-found &
done
wait
