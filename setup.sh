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

echo "==> Resetting audit log ConfigMap (prevents 1MB overflow across sessions)..."
kubectl delete configmap ztk8s-audit-log -n zerotrust-system --ignore-not-found

echo "==> Installing CRDs..."
make install

echo "==> Applying cluster-baseline ZeroTrustPolicy..."
kubectl apply -f config/samples/zerotrust_v1alpha1_zerotrustpolicy.yaml

echo ""
echo "Setup complete. Run 'make run' to start the controller."
echo "Wait for: reconcile cycle summary ... new_violations: 0"
