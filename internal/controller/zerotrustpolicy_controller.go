/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	zerotrustv1alpha1 "github.com/capstone/zerotrust-k8s/api/v1alpha1"
)

const (
	// clusterBaselineName is the default baseline instance expected in-cluster (see docs/architecture.md sample).
	clusterBaselineName = "cluster-baseline"
	// auditRequeueInterval is how often Phase 1 detection runs when the baseline exists.
	// DEFENSE NOTE: Aligns with architecture “reconciliation loop every 30s” for continuous drift detection.
	auditRequeueInterval = 30 * time.Second
)

// ZeroTrustPolicyReconciler reconciles a ZeroTrustPolicy object.
type ZeroTrustPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=zerotrust.capstone.io,resources=zerotrustpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zerotrust.capstone.io,resources=zerotrustpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zerotrust.capstone.io,resources=zerotrustpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=list;watch;get
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=list;watch;get
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=list;watch;get
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=list;watch;get
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=list;watch;get
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;create;update;patch

// Reconcile loads the cluster baseline policy and runs Phase 1 RBAC / NetworkPolicy detectors.
func (r *ZeroTrustPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if req.Name != clusterBaselineName {
		// Other ZeroTrustPolicy objects do not drive this controller’s Phase 1 loop yet.
		return ctrl.Result{}, nil
	}

	var policy zerotrustv1alpha1.ZeroTrustPolicy
	key := client.ObjectKey{Name: clusterBaselineName}
	if err := r.Get(ctx, key, &policy); err != nil {
		if apierrors.IsNotFound(err) {
			// DEFENSE NOTE: No baseline → nothing to enforce; requeue so applying `cluster-baseline` later starts detection without pod restart.
			logger.Info("ZeroTrustPolicy baseline not found yet; requeueing", "name", clusterBaselineName)
			return ctrl.Result{RequeueAfter: auditRequeueInterval}, nil
		}
		return ctrl.Result{}, err
	}

	events, err := r.runDetections(ctx, &policy)
	if err != nil {
		logger.Error(err, "detection pass failed", "name", clusterBaselineName)
		return ctrl.Result{}, err
	}

	rateLimit := remediationRateLimit(policy.Spec)
	autoFixedCount := 0
	escalatedCount := 0
	skippedCount := 0

	for _, event := range events {
		decision := Decide(event, policy.Spec)
		if autoFixedCount >= rateLimit {
			decision = RemediationDecision{
				Action:          DecisionActionEscalate,
				Reason:          "rate limit exceeded",
				SuggestedAction: event.SuggestedRemediation,
			}
		}

		switch decision.Action {
		case DecisionActionAutoFix:
			if err := r.applyRemediation(ctx, event); err != nil {
				return ctrl.Result{}, err
			}
			autoFixedCount++
		case DecisionActionEscalate:
			escalatedCount++
			if err := AppendAuditEntry(ctx, r.Client, AuditEntry{
				EntryID:                buildAuditEntryID(event),
				ViolationType:          event.ViolationType,
				RiskLevel:              event.RiskLevel,
				ResourceName:           event.ResourceName,
				Namespace:              event.Namespace,
				Action:                 "ESCALATED",
				Reason:                 decision.Reason,
				PreRemediationSnapshot: event.ResourceSnapshot,
				SuggestedAction:        decision.SuggestedAction,
				Timestamp:              time.Now().UTC(),
			}); err != nil {
				return ctrl.Result{}, err
			}
		case DecisionActionDryRun:
			if err := AppendAuditEntry(ctx, r.Client, AuditEntry{
				EntryID:                buildAuditEntryID(event),
				ViolationType:          event.ViolationType,
				RiskLevel:              event.RiskLevel,
				ResourceName:           event.ResourceName,
				Namespace:              event.Namespace,
				Action:                 "DRY_RUN",
				Reason:                 decision.Reason,
				PreRemediationSnapshot: event.ResourceSnapshot,
				SuggestedAction:        decision.SuggestedAction,
				Timestamp:              time.Now().UTC(),
			}); err != nil {
				return ctrl.Result{}, err
			}
		case DecisionActionSkip:
			skippedCount++
			if err := AppendAuditEntry(ctx, r.Client, AuditEntry{
				EntryID:                buildAuditEntryID(event),
				ViolationType:          event.ViolationType,
				RiskLevel:              event.RiskLevel,
				ResourceName:           event.ResourceName,
				Namespace:              event.Namespace,
				Action:                 "SKIPPED",
				Reason:                 decision.Reason,
				PreRemediationSnapshot: event.ResourceSnapshot,
				SuggestedAction:        decision.SuggestedAction,
				Timestamp:              time.Now().UTC(),
			}); err != nil {
				return ctrl.Result{}, err
			}
		default:
			escalatedCount++
			if err := AppendAuditEntry(ctx, r.Client, AuditEntry{
				EntryID:                buildAuditEntryID(event),
				ViolationType:          event.ViolationType,
				RiskLevel:              event.RiskLevel,
				ResourceName:           event.ResourceName,
				Namespace:              event.Namespace,
				Action:                 "ESCALATED",
				Reason:                 "unknown decision action; escalated by safety fallback",
				PreRemediationSnapshot: event.ResourceSnapshot,
				SuggestedAction:        event.SuggestedRemediation,
				Timestamp:              time.Now().UTC(),
			}); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	logger.Info(
		"reconcile cycle summary",
		"total_violations",
		len(events),
		"auto_fixed_count",
		autoFixedCount,
		"escalated_count",
		escalatedCount,
		"skipped_count",
		skippedCount,
	)

	return ctrl.Result{RequeueAfter: auditRequeueInterval}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ZeroTrustPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zerotrustv1alpha1.ZeroTrustPolicy{}).
		Named("zerotrustpolicy").
		Complete(r)
}

func remediationRateLimit(spec zerotrustv1alpha1.ZeroTrustPolicySpec) int {
	if spec.Remediation == nil || spec.Remediation.RateLimit == nil {
		return 5
	}
	limit := int(*spec.Remediation.RateLimit)
	if limit <= 0 {
		// DEFENSE NOTE: Never allow zero/negative rate limits to disable guardrails silently.
		return 1
	}
	return limit
}

func buildAuditEntryID(event ViolationEvent) string {
	normalizedResource := strings.ReplaceAll(event.ResourceName, "/", "-")
	normalizedResource = strings.ReplaceAll(normalizedResource, " ", "-")
	return fmt.Sprintf(
		"aud-%s-%s-%s",
		time.Now().UTC().Format("20060102150405"),
		strings.ToLower(event.ViolationType),
		strings.ToLower(normalizedResource),
	)
}
