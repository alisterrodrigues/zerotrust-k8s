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
	"encoding/json"
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

// applyRemediation executes supported AUTO_FIX actions.
func (r *ZeroTrustPolicyReconciler) applyRemediation(ctx context.Context, event ViolationEvent) error {
	if event.Namespace == "kube-system" {
		log.Warn().
			Str("violationType", event.ViolationType).
			Str("namespace", event.Namespace).
			Msg("skipping remediation in kube-system namespace")
		return nil
	}

	if event.ViolationType == "NP-001" {
		return r.applyDefaultDenyIngressForNP001(ctx, event)
	}

	if event.ViolationType == "RBAC-001" && event.RiskLevel == "LOW" {
		return r.removeWildcardVerbsForRBAC001Low(ctx, event)
	}

	log.Info().
		Str("violationType", event.ViolationType).
		Str("resourceName", event.ResourceName).
		Str("namespace", event.Namespace).
		Msg("no autofix implemented for type")
	return nil
}

func (r *ZeroTrustPolicyReconciler) applyDefaultDenyIngressForNP001(ctx context.Context, event ViolationEvent) error {
	var ns corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: event.Namespace}, &ns); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info().
				Str("violationType", event.ViolationType).
				Str("namespace", event.Namespace).
				Msg("namespace no longer exists; remediation is idempotent no-op")
			return nil
		}
		return err
	}
	if _, err := json.Marshal(ns); err != nil {
		return err
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
	if err := r.Patch(ctx, defaultDeny, client.Apply, client.FieldOwner(ssaFieldManagerName)); err != nil {
		return err
	}

	if err := AppendAuditEntry(ctx, r.Client, AuditEntry{
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
	}); err != nil {
		return err
	}

	log.Info().
		Str("violationType", "NP-001").
		Str("namespace", event.Namespace).
		Str("action", "AUTO_REMEDIATED").
		Msg("applied default-deny NetworkPolicy")
	return nil
}

func (r *ZeroTrustPolicyReconciler) removeWildcardVerbsForRBAC001Low(ctx context.Context, event ViolationEvent) error {
	var role rbacv1.ClusterRole
	if err := r.Get(ctx, types.NamespacedName{Name: event.ResourceName}, &role); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info().
				Str("violationType", event.ViolationType).
				Str("resourceName", event.ResourceName).
				Msg("ClusterRole no longer exists; remediation is idempotent no-op")
			return nil
		}
		return err
	}

	if !clusterRoleHasWildcardVerbs(role.Rules) {
		log.Info().
			Str("violationType", event.ViolationType).
			Str("resourceName", event.ResourceName).
			Msg("already remediated")
		return nil
	}

	patched := role.DeepCopy()
	for i := range patched.Rules {
		filtered := removeWildcardVerb(patched.Rules[i].Verbs)
		if len(filtered) == 0 {
			filtered = []string{"get", "list", "watch"}
		}
		patched.Rules[i].Verbs = filtered
	}

	// DEFENSE NOTE: RBAC-001 is a surgical edit of an existing role, so Update is clearer than SSA
	// full-state ownership. The snapshot in the audit entry is the rollback record for human recovery.
	if err := r.Update(ctx, patched); err != nil {
		return err
	}

	if err := AppendAuditEntry(ctx, r.Client, AuditEntry{
		EntryID:                remediationAuditEntryID("RBAC-001", event.ResourceName),
		ViolationType:          "RBAC-001",
		RiskLevel:              event.RiskLevel,
		ResourceName:           event.ResourceName,
		Namespace:              "",
		Action:                 "AUTO_REMEDIATED",
		Reason:                 "Removed wildcard verbs from ClusterRole",
		PreRemediationSnapshot: event.ResourceSnapshot,
		SuggestedAction:        "Review replaced verbs — default is get;list;watch",
		Timestamp:              time.Now().UTC(),
	}); err != nil {
		return err
	}

	log.Info().
		Str("violationType", "RBAC-001").
		Str("resourceName", event.ResourceName).
		Str("action", "AUTO_REMEDIATED").
		Msg("removed wildcard verbs from ClusterRole")
	return nil
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
	return fmt.Sprintf("aud-%s-%s-%s", time.Now().UTC().Format("20060102150405"), violationType, normalized)
}
