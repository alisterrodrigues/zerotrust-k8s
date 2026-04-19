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

	"github.com/rs/zerolog/log"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	defaultDenyIngressNetworkPolicyName = "ztk8s-default-deny-ingress"
	ssaFieldManagerName                 = "ztk8s-controller"
)

// applyRemediation executes supported AUTO_FIX actions and returns the AuditEntry to record,
// or nil if no action was taken (idempotent no-op or unimplemented type).
//
// DEFENSE NOTE: By returning the AuditEntry from the autofix functions instead of writing it
// inline, all audit writes for a cycle — whether from escalations, dry-runs, skips, or autofixes
// — flow through the single AppendAuditEntries batch call at the end of the reconcile loop.
// This guarantees at most one ConfigMap write per reconcile cycle regardless of how many
// violations were found or remediated.
func (r *ZeroTrustPolicyReconciler) applyRemediation(ctx context.Context, event ViolationEvent) (*AuditEntry, error) {
	// DEFENSE NOTE: This guard is intentional defense-in-depth. Under normal code paths,
	// kube-system violations get CRITICAL risk from np001Risk → SKIP from the decision
	// matrix → never reach applyRemediation. This guard exists as a secondary safety net
	// in case a future code path bypasses the decision matrix. Do not remove.
	if event.Namespace == "kube-system" {
		log.Warn().
			Str("violationType", event.ViolationType).
			Str("namespace", event.Namespace).
			Msg("skipping remediation in kube-system namespace")
		return nil, nil
	}

	if event.ViolationType == "NP-001" {
		entry, err := r.applyDefaultDenyIngressForNP001(ctx, event)
		if err != nil {
			return nil, err
		}
		return entry, nil
	}

	if event.ViolationType == "RBAC-001" && event.RiskLevel == "LOW" {
		entry, err := r.removeWildcardVerbsForRBAC001Low(ctx, event)
		if err != nil {
			return nil, err
		}
		return entry, nil
	}

	log.Info().
		Str("violationType", event.ViolationType).
		Str("resourceName", event.ResourceName).
		Str("namespace", event.Namespace).
		Msg("no autofix implemented for type")
	return nil, nil
}

// applyDefaultDenyIngressForNP001 applies a default-deny ingress NetworkPolicy to the namespace.
// Returns (nil, nil) when the action is a safe no-op (namespace gone, or policy already exists).
// Returns (*AuditEntry, nil) on success so the caller can batch the write.
func (r *ZeroTrustPolicyReconciler) applyDefaultDenyIngressForNP001(ctx context.Context, event ViolationEvent) (*AuditEntry, error) {
	var ns corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: event.Namespace}, &ns); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info().
				Str("violationType", event.ViolationType).
				Str("namespace", event.Namespace).
				Msg("namespace no longer exists; remediation is idempotent no-op")
			return nil, nil
		}
		return nil, err
	}

	// DEFENSE NOTE: Re-validate risk level immediately before mutation. The time
	// between detection and remediation spans multiple API calls. If a pod started
	// in this namespace during that window, np001Risk() now returns HIGH and
	// applying a default-deny policy without operator review would break new inbound
	// connections to a live workload. Re-checking here closes the TOCTOU window.
	currentRisk, riskErr := r.np001Risk(ctx, event.Namespace)
	if riskErr != nil {
		return nil, riskErr
	}
	if currentRisk != "LOW" {
		log.Info().
			Str("violationType", "NP-001").
			Str("namespace", event.Namespace).
			Str("detectedRisk", event.RiskLevel).
			Str("currentRisk", currentRisk).
			Msg("risk elevated between detection and remediation; aborting auto-fix")
		abortEntry := AuditEntry{
			EntryID:                remediationAuditEntryID("NP-001", event.Namespace),
			ViolationType:          "NP-001",
			RiskLevel:              currentRisk,
			ResourceName:           event.Namespace,
			Namespace:              event.Namespace,
			Action:                 "ESCALATED",
			Reason:                 fmt.Sprintf("risk elevated from LOW to %s after detection; a pod was created mid-cycle — auto-fix aborted to prevent disrupting live workloads", currentRisk),
			PreRemediationSnapshot: event.ResourceSnapshot,
			SuggestedAction:        "Apply a default-deny ingress NetworkPolicy manually with appropriate allow-rules for running workloads.",
			Timestamp:              time.Now().UTC(),
		}
		return &abortEntry, nil
	}

	defaultDeny := &netv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "networking.k8s.io/v1",
			Kind:       "NetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultDenyIngressNetworkPolicyName,
			Namespace: event.Namespace,
			Labels: map[string]string{
				"managed-by":  "ztk8s",
				"policy-type": "default-deny",
			},
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
			Ingress:     []netv1.NetworkPolicyIngressRule{},
		},
	}

	// DEFENSE NOTE: Server-Side Apply is used instead of Create/Update because it is declarative
	// and idempotent. Re-applying the same intent becomes a no-op rather than a duplicate-write error.
	// client.Apply is deprecated in newer controller-runtime versions in favour of r.Apply() but the
	// functional behaviour is identical; suppressed until the project upgrades controller-runtime.
	if err := r.Patch(ctx, defaultDeny, client.Apply, client.FieldOwner(ssaFieldManagerName)); err != nil { //nolint:staticcheck
		return nil, err
	}

	log.Info().
		Str("violationType", "NP-001").
		Str("namespace", event.Namespace).
		Str("action", "AUTO_REMEDIATED").
		Msg("applied default-deny NetworkPolicy")

	entry := AuditEntry{
		EntryID:                remediationAuditEntryID(event.ViolationType, defaultDenyIngressNetworkPolicyName),
		ViolationType:          event.ViolationType,
		RiskLevel:              event.RiskLevel,
		ResourceName:           defaultDenyIngressNetworkPolicyName,
		Namespace:              event.Namespace,
		Action:                 "AUTO_REMEDIATED",
		Reason:                 "Applied default-deny ingress NetworkPolicy to unprotected namespace",
		PreRemediationSnapshot: event.ResourceSnapshot,
		SuggestedAction:        "",
		Timestamp:              time.Now().UTC(),
	}
	return &entry, nil
}

// removeWildcardVerbsForRBAC001Low removes wildcard verbs from the named ClusterRole.
// Returns (nil, nil) when the action is a safe no-op (role gone, or already clean).
// Returns (*AuditEntry, nil) on success so the caller can batch the write.
func (r *ZeroTrustPolicyReconciler) removeWildcardVerbsForRBAC001Low(ctx context.Context, event ViolationEvent) (*AuditEntry, error) {
	var role rbacv1.ClusterRole
	if err := r.Get(ctx, types.NamespacedName{Name: event.ResourceName}, &role); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info().
				Str("violationType", event.ViolationType).
				Str("resourceName", event.ResourceName).
				Msg("ClusterRole no longer exists; remediation is idempotent no-op")
			return nil, nil
		}
		return nil, err
	}

	if !clusterRoleHasWildcardVerbs(role.Rules) {
		log.Info().
			Str("violationType", event.ViolationType).
			Str("resourceName", event.ResourceName).
			Msg("already remediated")
		return nil, nil
	}

	// DEFENSE NOTE: Re-validate binding state immediately before mutation. A
	// ClusterRoleBinding or RoleBinding may have been created after detection,
	// changing the risk from LOW (no bindings) to HIGH (active bindings).
	// Modifying a bound role would affect active subjects — always require human
	// review in that case rather than auto-patching.
	currentRisk, riskErr := r.rbac001Risk(ctx, event.ResourceName)
	if riskErr != nil {
		return nil, riskErr
	}
	if currentRisk != "LOW" {
		log.Info().
			Str("violationType", "RBAC-001").
			Str("resourceName", event.ResourceName).
			Str("detectedRisk", event.RiskLevel).
			Str("currentRisk", currentRisk).
			Msg("risk elevated between detection and remediation; aborting auto-fix")
		abortEntry := AuditEntry{
			EntryID:                remediationAuditEntryID("RBAC-001", event.ResourceName),
			ViolationType:          "RBAC-001",
			RiskLevel:              currentRisk,
			ResourceName:           event.ResourceName,
			Namespace:              "",
			Action:                 "ESCALATED",
			Reason:                 fmt.Sprintf("risk elevated from LOW to %s after detection; active bindings exist — auto-fix aborted to prevent authorization failures", currentRisk),
			PreRemediationSnapshot: event.ResourceSnapshot,
			SuggestedAction:        "A binding was created after detection. Review impacted subjects and patch role verbs manually.",
			Timestamp:              time.Now().UTC(),
		}
		return &abortEntry, nil
	}

	patched := role.DeepCopy()
	safeToFix := true
	for i := range patched.Rules {
		filtered := removeWildcardVerb(patched.Rules[i].Verbs)
		if len(filtered) == 0 {
			// DEFENSE NOTE: When * is the only verb in a rule, removing it would leave
			// the rule with no verbs, requiring us to invent a replacement. Inventing
			// verbs (e.g. get,list,watch) is unsafe — the original role may legitimately
			// need write access, and silently downgrading it can break workloads or
			// preserve unintended access. Escalate instead.
			safeToFix = false
			break
		}
		patched.Rules[i].Verbs = filtered
	}
	if !safeToFix {
		// DEFENSE NOTE: When * is the only verb in a rule, we cannot safely remove it
		// without inventing a replacement. Rather than silently returning nil (which
		// produces no audit entry and no metric), we return a SKIPPED AuditEntry so the
		// normal audit/metric pipeline is exercised and operators can see the decision.
		// This also prevents the rate limit token from being consumed by a no-op — the
		// caller only increments autoFixedCount when remAuditEntry != nil.
		log.Info().
			Str("violationType", "RBAC-001").
			Str("resourceName", event.ResourceName).
			Msg("wildcard-only verb rule — cannot safely remove without inventing verbs; recording SKIPPED")
		entry := AuditEntry{
			EntryID:                remediationAuditEntryID("RBAC-001", event.ResourceName),
			ViolationType:          "RBAC-001",
			RiskLevel:              event.RiskLevel,
			ResourceName:           event.ResourceName,
			Namespace:              "",
			Action:                 "SKIPPED",
			Reason:                 "wildcard-only verb rule — no safe replacement without inventing verbs; manual review required",
			PreRemediationSnapshot: event.ResourceSnapshot,
			SuggestedAction:        "Manually replace the wildcard verb with an explicit least-privilege verb list.",
			Timestamp:              time.Now().UTC(),
		}
		return &entry, nil
	}

	// DEFENSE NOTE: RBAC-001 is a surgical edit of an existing role, so Update is clearer than SSA
	// full-state ownership. The snapshot in the audit entry is the rollback record for human recovery.
	if err := r.Update(ctx, patched); err != nil {
		return nil, err
	}

	log.Info().
		Str("violationType", "RBAC-001").
		Str("resourceName", event.ResourceName).
		Str("action", "AUTO_REMEDIATED").
		Msg("removed wildcard verbs from ClusterRole")

	entry := AuditEntry{
		EntryID:                remediationAuditEntryID("RBAC-001", event.ResourceName),
		ViolationType:          "RBAC-001",
		RiskLevel:              event.RiskLevel,
		ResourceName:           event.ResourceName,
		Namespace:              "",
		Action:                 "AUTO_REMEDIATED",
		Reason:                 "Removed wildcard verbs from ClusterRole",
		PreRemediationSnapshot: event.ResourceSnapshot,
		SuggestedAction:        "Wildcard verbs removed. If any rule is now empty, add explicit least-privilege verbs (e.g. get, list, watch) appropriate for this role's purpose.",
		Timestamp:              time.Now().UTC(),
	}
	return &entry, nil
}

func clusterRoleHasWildcardVerbs(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		for _, verb := range rule.Verbs {
			if verb == rbacv1.VerbAll {
				return true
			}
		}
	}
	return false
}

func removeWildcardVerb(verbs []string) []string {
	out := make([]string, 0, len(verbs))
	for _, verb := range verbs {
		if verb == rbacv1.VerbAll {
			continue
		}
		out = append(out, verb)
	}
	return out
}

func remediationAuditEntryID(violationType, resourceName string) string {
	normalized := strings.ReplaceAll(resourceName, "/", "-")
	normalized = strings.ReplaceAll(normalized, " ", "-")
	return fmt.Sprintf("aud-%s-%s-%s", time.Now().UTC().Format("20060102150405.000000000"), violationType, normalized)
}
