#!/usr/bin/env bash
# setup.sh — Run this once before every development session.
# Creates required namespaces, resets the audit log, and verifies the cluster is reachable.
# Safe to run multiple times — all operations are idempotent.

set -euo pipefail

echo "==> Checking minikube is running..."
if ! kubectl cluster-info &>/dev/null; then
  echo "ERROR: kubectl cannot reach a cluster."
  echo "Run: minikube start --driver=docker"
  exit 1
fi

echo "==> Creating zerotrust-system namespace (idempotent)..."
kubectl create namespace zerotrust-system --dry-run=client -o yaml | kubectl apply -f -

echo "==> Creating test namespaces (idempotent)..."
kubectl create namespace test-remediation --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace test-low-risk --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace test-high-risk --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace test-exempt --dry-run=client -o yaml | kubectl apply -f -

echo "==> Resetting audit log ConfigMaps (prevents accumulation across sessions)..."
# Delete the base ConfigMap and ALL numbered rotation ConfigMaps (ztk8s-audit-log-2, -3, etc.)
# The controller creates these automatically; stale ones from prior sessions cause
# currentAuditConfigMapName() to resume writing to an old object instead of starting fresh.
kubectl delete configmap ztk8s-audit-log -n zerotrust-system --ignore-not-found
for i in $(seq 2 20); do
  kubectl delete configmap "ztk8s-audit-log-${i}" -n zerotrust-system --ignore-not-found 2>/dev/null || true
done

echo "==> Cleaning up stale evaluation ClusterRoles from prior sessions..."
# eval-rbac001-* ClusterRoles accumulate when Scenario 02 times out before cleanup runs.
# These leave stale RBAC-001 violations silently suppressed in seenViolations across sessions.
kubectl get clusterrole -o name 2>/dev/null | grep "clusterrole/eval-rbac001-" | \
  xargs -r kubectl delete --ignore-not-found 2>/dev/null || true

echo "==> Installing CRDs..."
make install

echo "==> Applying cluster-baseline ZeroTrustPolicy..."
kubectl apply -f config/samples/zerotrust_v1alpha1_zerotrustpolicy.yaml

echo ""
echo "Setup complete. Run 'make run' to start the controller."
echo "Wait for: reconcile cycle summary ... new_violations: 0"
