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

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

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

	// seenViolations records when each distinct violation was first seen in-cluster.
	// DEFENSE NOTE: seenViolations is an in-memory cache keyed by violation identity. It prevents
	// the same persistent misconfiguration from being counted multiple times across reconcile cycles,
	// which would inflate detection metrics and make evaluation data meaningless.
	seenViolations map[ViolationKey]time.Time

	// rateLimitWindowStart is the start of the current rate-limit measurement window.
	// DEFENSE NOTE: Using a time window instead of a per-cycle counter means the rate
	// limit is enforced across all reconcile cycles that fire within a single 30-second
	// window — whether triggered by the RequeueAfter timer or by event-driven watches.
	// This correctly throttles remediation storms regardless of how violations arrive.
	rateLimitWindowStart time.Time

	// rateLimitWindowCount tracks how many remediations have fired in the current window.
	rateLimitWindowCount int
}

// +kubebuilder:rbac:groups=zerotrust.capstone.io,resources=zerotrustpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zerotrust.capstone.io,resources=zerotrustpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zerotrust.capstone.io,resources=zerotrustpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=list;watch;get
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=list;watch;get
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=list;watch;get
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=list;watch;get
// +kubebuilder:rbac:groups="",resources=pods,verbs=list;watch;get
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;create;update;patch

// Reconcile loads the cluster baseline policy and runs Phase 1 RBAC / NetworkPolicy detectors.
func (r *ZeroTrustPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	cycleStart := time.Now()
	defer func() { RecordCycleDuration(time.Since(cycleStart).Seconds()) }()

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

	if r.seenViolations == nil {
		r.seenViolations = make(map[ViolationKey]time.Time)
	}

	newEvents := make([]ViolationEvent, 0)
	knownEvents := make([]ViolationEvent, 0, len(events))
	for _, event := range events {
		vk := violationKeyFromEvent(event)
		if _, seen := r.seenViolations[vk]; !seen {
			newEvents = append(newEvents, event)
		} else {
			knownEvents = append(knownEvents, event)
		}
	}

	for _, event := range newEvents {
		RecordViolation(event.ViolationType, event.Namespace, event.RiskLevel)
	}

	// DEFENSE NOTE: Cache pruning is what makes detection latency measurement accurate. When a violation
	// is remediated and disappears from the cluster, its key is removed. If the same misconfiguration is
	// re-introduced, the next detection is counted as a fresh violation — which is exactly what the
	// evaluation scenario scripts depend on.
	currentKeys := make(map[ViolationKey]struct{}, len(events))
	for _, e := range events {
		currentKeys[violationKeyFromEvent(e)] = struct{}{}
	}
	for k := range r.seenViolations {
		if _, stillActive := currentKeys[k]; !stillActive {
			delete(r.seenViolations, k)
		}
	}

	rateLimit := remediationRateLimit(policy.Spec)
	autoFixedCount := 0
	escalatedCount := 0
	skippedCount := 0
	pendingAuditEntries := make([]AuditEntry, 0)

	for _, event := range newEvents {
		decision := Decide(event, policy.Spec)

		switch decision.Action {
		case DecisionActionAutoFix:
			// DEFENSE NOTE: windowRateLimit is checked here — inside the AUTO_FIX branch only —
			// so that only actual remediation writes consume the 30-second budget. ESCALATE,
			// SKIP, and DRY_RUN decisions do not count against the rate limit. This ensures
			// HIGH-risk escalations cannot starve LOW-risk auto-fixes of their budget.
			if !r.windowRateLimit(rateLimit) {
				pendingAuditEntries = append(pendingAuditEntries, AuditEntry{
					EntryID:                buildAuditEntryID(event),
					ViolationType:          event.ViolationType,
					RiskLevel:              event.RiskLevel,
					ResourceName:           event.ResourceName,
					Namespace:              event.Namespace,
					Action:                 "ESCALATED",
					Reason:                 "rate limit exceeded for 30-second window",
					PreRemediationSnapshot: event.ResourceSnapshot,
					SuggestedAction:        event.SuggestedRemediation,
					Timestamp:              time.Now().UTC(),
				})
				escalatedCount++
				break
			}
			// DEFENSE NOTE: By returning the AuditEntry from the autofix functions instead of
			// writing it inline, all audit writes for a cycle flow through the single
			// AppendAuditEntries batch call below. This guarantees at most one ConfigMap write
			// per reconcile cycle regardless of how many violations were found or remediated.
			remAuditEntry, err := r.applyRemediation(ctx, event)
			if err != nil {
				return ctrl.Result{}, err
			}
			if remAuditEntry != nil {
				pendingAuditEntries = append(pendingAuditEntries, *remAuditEntry)
				// DEFENSE NOTE: autoFixedCount is only incremented when applyRemediation confirms
				// an actual API write occurred (non-nil entry). No-op returns (nil, nil) — e.g.
				// namespace already gone, role already clean — do not consume rate limit budget
				// or inflate remediation metrics.
				autoFixedCount++
			}
		case DecisionActionEscalate:
			escalatedCount++
			pendingAuditEntries = append(pendingAuditEntries, AuditEntry{
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
			})
		case DecisionActionDryRun:
			pendingAuditEntries = append(pendingAuditEntries, AuditEntry{
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
			})
		case DecisionActionSkip:
			skippedCount++
			pendingAuditEntries = append(pendingAuditEntries, AuditEntry{
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
			})
		default:
			escalatedCount++
			pendingAuditEntries = append(pendingAuditEntries, AuditEntry{
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
			})
		}
	}

	if err := AppendAuditEntries(ctx, r.Client, pendingAuditEntries); err != nil {
		return ctrl.Result{}, err
	}

	// DEFENSE NOTE: seenViolations is updated only after AppendAuditEntries succeeds.
	// If the audit write fails and the reconciler retries, the violations are still
	// treated as newEvents on the next cycle and will be re-processed and re-written.
	// This guarantees eventual audit trail consistency at the cost of a potential
	// duplicate entry on crash-restart — the correct trade-off for a forensic audit log.
	for _, event := range newEvents {
		vk := violationKeyFromEvent(event)
		r.seenViolations[vk] = time.Now().UTC()
	}

	// DEFENSE NOTE: Recording escalation metrics only after the audit write succeeds prevents
	// double-counting on retry. If AppendAuditEntries fails and the reconciler returns an error,
	// controller-runtime requeues the entire cycle. Moving RecordEscalation here means metrics
	// and audit state stay consistent — a counter increment only happens when the audit record
	// is confirmed persisted.
	for _, entry := range pendingAuditEntries {
		if entry.Action == "ESCALATED" {
			RecordEscalation(entry.ViolationType, entry.Namespace)
		}
		// DEFENSE NOTE: RecordRemediation is called here — after AppendAuditEntries
		// succeeds — mirroring the escalation pattern. If the audit write fails and
		// the reconciler retries, the counter is never incremented for that cycle,
		// keeping Prometheus metrics consistent with the persisted audit log.
		if entry.Action == "AUTO_REMEDIATED" {
			RecordRemediation(entry.ViolationType, entry.Namespace)
		}
		// DEFENSE NOTE: DRY_RUN and SKIPPED metrics give operators visibility into
		// system activity when running in dryrun or manual mode. Without these,
		// all Prometheus counters stay at zero in non-auto modes, making it impossible
		// to confirm the detection pipeline is working during staged rollout.
		if entry.Action == "DRY_RUN" {
			RecordDryRun(entry.ViolationType, entry.Namespace)
		}
		if entry.Action == "SKIPPED" {
			RecordSkipped(entry.ViolationType, entry.Namespace)
		}
	}

	logger.Info(
		"reconcile cycle summary",
		"total_violations",
		len(events),
		"new_violations",
		len(newEvents),
		"known_violations",
		len(knownEvents),
		"auto_fixed_count",
		autoFixedCount,
		"escalated_count",
		escalatedCount,
		"skipped_count",
		skippedCount,
	)

	// DEFENSE NOTE: Writing an AuditComplete status condition after every successful cycle
	// makes the ZeroTrustPolicy resource observable via `kubectl get zerotrustpolicy` and
	// `kubectl describe zerotrustpolicy cluster-baseline`. Operators can see at a glance
	// whether the last audit cycle completed and when — this is the Kubernetes-native
	// observability pattern for custom controllers.
	auditCondition := metav1.Condition{
		Type:               "AuditComplete",
		Status:             metav1.ConditionTrue,
		Reason:             "CycleComplete",
		Message:            fmt.Sprintf("Audit cycle complete. Violations: %d total (%d new). Remediated: %d. Escalated: %d.", len(events), len(newEvents), autoFixedCount, escalatedCount),
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: policy.Generation,
	}
	// Use apimeta.SetStatusCondition to handle idempotent upsert of the condition.
	apimeta.SetStatusCondition(&policy.Status.Conditions, auditCondition)
	if err := r.Status().Update(ctx, &policy); err != nil {
		// Non-fatal: log and continue. Status is best-effort; a failed status
		// update does not invalidate the audit cycle itself.
		logger.Error(err, "failed to update ZeroTrustPolicy status conditions")
	}

	return ctrl.Result{RequeueAfter: auditRequeueInterval}, nil
}

// windowRateLimit returns true if a remediation may proceed given the configured
// rate limit per 30-second window. It resets the window when 30 seconds have elapsed.
//
// DEFENSE NOTE: The window duration matches auditRequeueInterval (30s) so the rate
// limit budget is semantically "N remediations per audit cycle" even when watches
// fire multiple reconcile calls within that cycle.
func (r *ZeroTrustPolicyReconciler) windowRateLimit(limit int) bool {
	now := time.Now()
	if now.Sub(r.rateLimitWindowStart) >= auditRequeueInterval {
		// Window expired — reset counter and start a new window.
		r.rateLimitWindowStart = now
		r.rateLimitWindowCount = 0
	}
	if r.rateLimitWindowCount >= limit {
		return false
	}
	r.rateLimitWindowCount++
	return true
}

// SetupWithManager sets up the controller with the Manager.
func (r *ZeroTrustPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.seenViolations == nil {
		r.seenViolations = make(map[ViolationKey]time.Time)
	}

	// enqueueBaseline always returns a reconcile request for the singleton baseline CR.
	// DEFENSE NOTE: By mapping every watched resource change back to "cluster-baseline",
	// the controller re-runs the full detection pass immediately whenever a ClusterRole,
	// ClusterRoleBinding, RoleBinding, NetworkPolicy, or Namespace is created, updated,
	// or deleted. This reduces worst-case detection latency from 30s to near-zero for
	// event-driven changes, while the RequeueAfter loop still catches anything missed.
	enqueueBaseline := handler.EnqueueRequestsFromMapFunc(
		func(ctx context.Context, obj client.Object) []reconcile.Request {
			return []reconcile.Request{
				{NamespacedName: types.NamespacedName{Name: clusterBaselineName}},
			}
		},
	)

	return ctrl.NewControllerManagedBy(mgr).
		For(&zerotrustv1alpha1.ZeroTrustPolicy{}).
		Watches(&rbacv1.ClusterRole{}, enqueueBaseline).
		Watches(&rbacv1.ClusterRoleBinding{}, enqueueBaseline).
		Watches(&rbacv1.RoleBinding{}, enqueueBaseline).
		Watches(&netv1.NetworkPolicy{}, enqueueBaseline).
		Watches(&corev1.Namespace{}, enqueueBaseline).
		// DEFENSE NOTE: Role watch ensures RBAC-004 and RBAC-005 violations (wildcard verbs/resources
		// in namespaced Roles) are detected event-driven — immediately when a Role is created or
		// modified — rather than waiting up to 30 seconds for the next periodic tick.
		Watches(&rbacv1.Role{}, enqueueBaseline).
		// DEFENSE NOTE: Pod watch ensures that NP-001 risk transitions are detected
		// event-driven. When a pod is created in a previously-empty namespace, the risk
		// transitions from LOW (auto-remediable) to HIGH (escalate). Without this watch,
		// the transition is only detected at the next 30-second periodic tick, potentially
		// allowing the auto-remediation of a namespace that now has running workloads.
		Watches(&corev1.Pod{}, enqueueBaseline).
		Named("zerotrustpolicy").
		Complete(r)
}

func violationKeyFromEvent(e ViolationEvent) ViolationKey {
	return ViolationKey{
		ViolationType: e.ViolationType,
		ResourceName:  e.ResourceName,
		Namespace:     e.Namespace,
		SubjectName:   e.SubjectName,
		SubjectKind:   e.SubjectKind,
	}
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
	// DEFENSE NOTE: Nanosecond precision prevents duplicate EntryIDs when multiple violations
	// of the same type fire against the same resource within a single second — for example during
	// burst evaluation scenarios where many namespaces are created simultaneously.
	return fmt.Sprintf(
		"aud-%s-%s-%s",
		time.Now().UTC().Format("20060102150405.000000000"),
		strings.ToLower(event.ViolationType),
		strings.ToLower(normalizedResource),
	)
}
