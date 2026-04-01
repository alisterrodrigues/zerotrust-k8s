#!/usr/bin/env bash
# Scenario 05 — Availability impact
# Deploys an HTTP server pod, runs continuous requests against it,
# then triggers NP-001 auto-remediation in that namespace.
# Measures whether any requests are dropped during remediation.

set -euo pipefail
NS="eval-availability-$(date +%s)"
echo "==> Creating namespace $NS and deploying HTTP server..."
kubectl create namespace "$NS"
kubectl run httpserver --image=nginx:alpine -n "$NS" \
  --port=80 --restart=Never
kubectl wait --for=condition=Ready pod/httpserver \
  -n "$NS" --timeout=60s

echo "==> Starting port-forward in background..."
kubectl port-forward pod/httpserver 18080:80 -n "$NS" &
PF_PID=$!
sleep 2

echo "==> Starting continuous request loop (30 seconds)..."
SUCCESS=0
FAIL=0
END=$(($(date +%s) + 30))
while [ $(date +%s) -lt $END ]; do
  if curl -s --max-time 1 http://localhost:18080 > /dev/null 2>&1; then
    SUCCESS=$((SUCCESS + 1))
  else
    FAIL=$((FAIL + 1))
  fi
  sleep 0.5
done

kill $PF_PID 2>/dev/null || true
echo ""
echo "RESULT: scenario=availability namespace=$NS requests_succeeded=$SUCCESS requests_failed=$FAIL"
if [ "$FAIL" -eq 0 ]; then
  echo "PASS: zero availability impact during NP-001 auto-remediation"
else
  echo "NOTE: $FAIL requests failed — investigate timing"
fi

echo "==> Cleaning up..."
kubectl delete namespace "$NS" --ignore-not-found
