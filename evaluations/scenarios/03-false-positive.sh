#!/usr/bin/env bash
# Scenario 03 — False positive rate
# Applies resources that should be EXEMPT and verifies no violations
# are triggered for them. Ground truth: we designed these, so we know
# they should be exempt.

set -euo pipefail
PASS=0
FAIL=0

echo "==> Test 1: test-exempt namespace should not trigger NP-001"
# Wait one full cycle (35s to be safe) and check metrics
sleep 35
NP_EXEMPT=$(curl -s http://localhost:8080/metrics \
  | grep 'ztk8s_violations_total' \
  | grep 'test-exempt' || true)
if [ -z "$NP_EXEMPT" ]; then
  echo "PASS: test-exempt not in violation metrics"
  PASS=$((PASS + 1))
else
  echo "FAIL: test-exempt found in violation metrics: $NP_EXEMPT"
  FAIL=$((FAIL + 1))
fi

echo "==> Test 2: kube-system namespace should not be auto-remediated"
KS_REMEDIATED=$(kubectl get networkpolicy ztk8s-default-deny-ingress \
  -n kube-system 2>/dev/null || true)
if [ -z "$KS_REMEDIATED" ]; then
  echo "PASS: kube-system not auto-remediated"
  PASS=$((PASS + 1))
else
  echo "FAIL: kube-system has auto-applied NetworkPolicy"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "RESULT: false_positive_tests=$((PASS + FAIL)) passed=$PASS failed=$FAIL"
echo "FALSE_POSITIVE_RATE=$(echo "scale=2; $FAIL / ($PASS + $FAIL)" | bc)"
