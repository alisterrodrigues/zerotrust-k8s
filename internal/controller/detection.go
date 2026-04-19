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
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	zerotrustv1alpha1 "github.com/capstone/zerotrust-k8s/api/v1alpha1"
)

const clusterAdminClusterRole = "cluster-admin"

// runDetections executes Phase 1 RBAC and NetworkPolicy checks driven by the baseline CR.
func (r *ZeroTrustPolicyReconciler) runDetections(ctx context.Context, policy *zerotrustv1alpha1.ZeroTrustPolicy) ([]ViolationEvent, error) {
	events := make([]ViolationEvent, 0)

	if policy.Spec.RBAC != nil {
		if boolPtrVal(policy.Spec.RBAC.DenyWildcardVerbs, false) || boolPtrVal(policy.Spec.RBAC.DenyWildcardResources, false) {
			wildcardEvents, err := r.detectWildcardClusterRoles(ctx, policy.Spec.RBAC)
			if err != nil {
				return nil, err
			}
			events = append(events, wildcardEvents...)
		}
		if boolPtrVal(policy.Spec.RBAC.DenyWildcardVerbs, false) || boolPtrVal(policy.Spec.RBAC.DenyWildcardResources, false) {
			namespacedEvents, err := r.detectWildcardNamespacedRoles(ctx, policy.Spec.RBAC)
			if err != nil {
				return nil, err
			}
			events = append(events, namespacedEvents...)
		}
		cfg := policy.Spec.RBAC.DenyClusterAdminBinding
		if cfg != nil {
			bindingEvents, err := r.detectClusterAdminBindings(ctx, cfg.ExcludeServiceAccounts)
			if err != nil {
				return nil, err
			}
			events = append(events, bindingEvents...)
		}
		if boolPtrVal(policy.Spec.RBAC.RequireNamespacedRoles, false) {
			namespacedRoleEvents, err := r.detectRequireNamespacedRoles(ctx)
			if err != nil {
				return nil, err
			}
			events = append(events, namespacedRoleEvents...)
		}
	}

	if policy.Spec.NetworkPolicy != nil {
		if boolPtrVal(policy.Spec.NetworkPolicy.RequireDefaultDenyIngress, false) {
			networkEvents, err := r.detectNamespacesWithoutNetworkPolicy(ctx, policy)
			if err != nil {
				return nil, err
			}
			events = append(events, networkEvents...)
		}
		if boolPtrVal(policy.Spec.NetworkPolicy.RequireDefaultDenyEgress, false) {
			egressEvents, err := r.detectNamespacesWithoutEgressPolicy(ctx, policy)
			if err != nil {
				return nil, err
			}
			events = append(events, egressEvents...)
		}
	}

	return events, nil
}

// detectWildcardClusterRoles implements RBAC-001 (wildcard verbs) and RBAC-002 (wildcard resources)
// on ClusterRole objects only, per Phase 1 scope. rbacSpec gates which violation types are emitted.
func (r *ZeroTrustPolicyReconciler) detectWildcardClusterRoles(ctx context.Context, rbacSpec *zerotrustv1alpha1.RBACSpec) ([]ViolationEvent, error) {
	var list rbacv1.ClusterRoleList
	if err := r.List(ctx, &list); err != nil {
		return nil, err
	}

	events := make([]ViolationEvent, 0)
	for i := range list.Items {
		cr := &list.Items[i]
		hasWildcardVerb, hasWildcardResource := clusterRoleWildcardFlags(cr)

		if hasWildcardVerb && boolPtrVal(rbacSpec.DenyWildcardVerbs, false) {
			risk, err := r.rbac001Risk(ctx, cr.Name)
			if err != nil {
				return nil, err
			}
			event, err := newViolationEvent(
				"RBAC-001",
				cr.Name,
				"",
				risk,
				cr,
				"Remove wildcard verbs from ClusterRole rules and replace with explicit least-privilege verbs.",
			)
			if err != nil {
				return nil, err
			}
			events = append(events, event)
		}
		if hasWildcardResource && boolPtrVal(rbacSpec.DenyWildcardResources, false) {
			// DEFENSE NOTE: RBAC-002 is now independently controlled by DenyWildcardResources.
			// Previously both RBAC-001 and RBAC-002 were gated on DenyWildcardVerbs, which meant
			// RBAC-002 could not be disabled without also disabling RBAC-001. This CRD design fix
			// makes each check independently toggleable.
			event, err := newViolationEvent(
				"RBAC-002",
				cr.Name,
				"",
				"HIGH",
				cr,
				"Remove wildcard resources from ClusterRole rules and scope access to explicit resources only.",
			)
			if err != nil {
				return nil, err
			}
			events = append(events, event)
		}
	}
	return events, nil
}

func clusterRoleWildcardFlags(cr *rbacv1.ClusterRole) (hasWildcardVerb, hasWildcardResource bool) {
	for _, rule := range cr.Rules {
		if stringSliceContains(rule.Verbs, rbacv1.VerbAll) {
			hasWildcardVerb = true
		}
		if stringSliceContains(rule.Resources, rbacv1.ResourceAll) {
			hasWildcardResource = true
		}
	}
	return hasWildcardVerb, hasWildcardResource
}

// detectWildcardNamespacedRoles implements RBAC-004 (wildcard verbs) and RBAC-005
// (wildcard resources) on namespaced Role objects across all namespaces.
// rbacSpec gates which violation types are emitted independently.
//
// DEFENSE NOTE: RBAC-001/002 only cover ClusterRoles. A developer can bypass
// cluster-level detection entirely by creating a namespaced Role with wildcard
// verbs in their own namespace. RBAC-004/005 close this gap by scanning every
// Role in every namespace using the same wildcard logic applied to ClusterRoles.
func (r *ZeroTrustPolicyReconciler) detectWildcardNamespacedRoles(ctx context.Context, rbacSpec *zerotrustv1alpha1.RBACSpec) ([]ViolationEvent, error) {
	// DEFENSE NOTE: A single cluster-wide List is O(1) API calls regardless of namespace
	// count. The informer cache makes this call local (no network round-trip). This replaces
	// the previous O(N namespaces) loop that issued one API call per namespace.
	var roleList rbacv1.RoleList
	if err := r.List(ctx, &roleList); err != nil {
		return nil, err
	}

	events := make([]ViolationEvent, 0)
	for j := range roleList.Items {
		role := &roleList.Items[j]
		nsName := role.Namespace
		hasWildcardVerb, hasWildcardResource := namespacedRoleWildcardFlags(role)

		if hasWildcardVerb && boolPtrVal(rbacSpec.DenyWildcardVerbs, false) {
			event, err := newViolationEvent(
				"RBAC-004",
				role.Name,
				nsName,
				"HIGH",
				role,
				"Remove wildcard verbs from namespaced Role and replace with explicit least-privilege verbs.",
			)
			if err != nil {
				return nil, err
			}
			events = append(events, event)
		}
		if hasWildcardResource && boolPtrVal(rbacSpec.DenyWildcardResources, false) {
			event, err := newViolationEvent(
				"RBAC-005",
				role.Name,
				nsName,
				"HIGH",
				role,
				"Remove wildcard resources from namespaced Role and scope access to explicit resources only.",
			)
			if err != nil {
				return nil, err
			}
			events = append(events, event)
		}
	}
	return events, nil
}

func namespacedRoleWildcardFlags(role *rbacv1.Role) (hasWildcardVerb, hasWildcardResource bool) {
	for _, rule := range role.Rules {
		if stringSliceContains(rule.Verbs, rbacv1.VerbAll) {
			hasWildcardVerb = true
		}
		if stringSliceContains(rule.Resources, rbacv1.ResourceAll) {
			hasWildcardResource = true
		}
	}
	return hasWildcardVerb, hasWildcardResource
}

// rbac001Risk maps RBAC-001 to LOW / HIGH / CRITICAL using docs/remediation-model.md.
func (r *ZeroTrustPolicyReconciler) rbac001Risk(ctx context.Context, clusterRoleName string) (string, error) {
	// Names starting with "system:" are Kubernetes reserved / control-plane roles.
	if strings.HasPrefix(clusterRoleName, "system:") {
		return "CRITICAL", nil
	}
	bound, err := r.clusterRoleHasBindings(ctx, clusterRoleName)
	if err != nil {
		return "", err
	}
	if bound {
		return "HIGH", nil
	}
	return "LOW", nil
}

// clusterRoleHasBindings returns true if any ClusterRoleBinding or RoleBinding references this ClusterRole.
func (r *ZeroTrustPolicyReconciler) clusterRoleHasBindings(ctx context.Context, clusterRoleName string) (bool, error) {
	var crbList rbacv1.ClusterRoleBindingList
	if err := r.List(ctx, &crbList); err != nil {
		return false, err
	}
	for i := range crbList.Items {
		if roleRefPointsToClusterRole(crbList.Items[i].RoleRef, clusterRoleName) {
			return true, nil
		}
	}

	// DEFENSE NOTE: A single cluster-wide List is O(1) API calls regardless of namespace
	// count, compared to the previous O(N) loop which issued one API call per namespace.
	// In clusters with hundreds of namespaces this is a significant scalability improvement.
	// controller-runtime's informer cache makes this call local (no network round-trip).
	var rbList rbacv1.RoleBindingList
	if err := r.List(ctx, &rbList); err != nil {
		return false, err
	}
	for i := range rbList.Items {
		if roleRefPointsToClusterRole(rbList.Items[i].RoleRef, clusterRoleName) {
			return true, nil
		}
	}
	return false, nil
}

func roleRefPointsToClusterRole(ref rbacv1.RoleRef, clusterRoleName string) bool {
	// RoleRef.Kind defaults to ClusterRole when empty (see k8s.io/api/rbac/v1 RoleRef).
	kind := ref.Kind
	if kind == "" || kind == "ClusterRole" {
		return ref.Name == clusterRoleName
	}
	return false
}

// detectClusterAdminBindings implements RBAC-003: cluster-admin bound to a subject not in the exclude list.
func (r *ZeroTrustPolicyReconciler) detectClusterAdminBindings(ctx context.Context, excludePatterns []string) ([]ViolationEvent, error) {
	var list rbacv1.ClusterRoleBindingList
	if err := r.List(ctx, &list); err != nil {
		return nil, err
	}

	events := make([]ViolationEvent, 0)
	for i := range list.Items {
		crb := &list.Items[i]
		if !roleRefPointsToClusterRole(crb.RoleRef, clusterAdminClusterRole) {
			continue
		}
		for _, sub := range crb.Subjects {
			if subjectMatchesExclusion(sub, excludePatterns) {
				continue
			}
			risk := rbac003Risk(sub)
			// ClusterRoleBinding is cluster-scoped; namespace field on the binding is empty.
			event, err := newViolationEvent(
				"RBAC-003",
				crb.Name,
				subjectNamespaceForLog(sub),
				risk,
				crb,
				"Review non-whitelisted cluster-admin binding and revoke or scope it to least privilege.",
			)
			if err != nil {
				return nil, err
			}
			// DEFENSE NOTE: Populate SubjectName/SubjectKind so each offending subject
			// gets its own deduplication key. Without this, a binding with 3 bad subjects
			// would only track 1 violation after the first cycle.
			event.SubjectName = sub.Name
			event.SubjectKind = sub.Kind
			events = append(events, event)
		}
	}
	// DEFENSE NOTE: A namespaced RoleBinding can reference cluster-admin as its roleRef.
	// This is uncommon but valid Kubernetes and grants cluster-admin permissions scoped
	// to the namespace of the binding. Without checking namespaced RoleBindings, an
	// attacker who creates such a binding is completely invisible to RBAC-003 detection.
	// DEFENSE NOTE: Single cluster-wide RoleBindingList — O(1) API calls.
	// Mirrors the fix applied to clusterRoleHasBindings in the previous audit round.
	var allRBList rbacv1.RoleBindingList
	if err := r.List(ctx, &allRBList); err != nil {
		return nil, err
	}
	for j := range allRBList.Items {
		rb := &allRBList.Items[j]
		if !roleRefPointsToClusterRole(rb.RoleRef, clusterAdminClusterRole) {
			continue
		}
		for _, sub := range rb.Subjects {
			if subjectMatchesExclusion(sub, excludePatterns) {
				continue
			}
			risk := rbac003Risk(sub)
			event, err := newViolationEvent(
				"RBAC-003",
				rb.Name,
				rb.Namespace,
				risk,
				rb,
				"Review non-whitelisted cluster-admin RoleBinding and revoke or scope it.",
			)
			if err != nil {
				return nil, err
			}
			event.SubjectName = sub.Name
			event.SubjectKind = sub.Kind
			events = append(events, event)
		}
	}

	return events, nil
}

// detectRequireNamespacedRoles implements the RequireNamespacedRoles enforcement:
// it scans all ClusterRoleBindings and flags any that bind a non-system user or
// service account to a non-system ClusterRole, suggesting the binding could instead
// reference a namespaced Role scoped to the relevant namespace.
//
// DEFENSE NOTE: RequireNamespacedRoles is a Zero Trust "least privilege" principle —
// cluster-scoped roles grant permissions in ALL namespaces. Any ClusterRoleBinding
// for application workloads (non-system) is a candidate for downscoping to a
// namespaced Role+RoleBinding pair. This detector surfaces those cases for human review;
// it does not auto-remediate because the correct scoped replacement depends on workload intent.
func (r *ZeroTrustPolicyReconciler) detectRequireNamespacedRoles(ctx context.Context) ([]ViolationEvent, error) {
	var crbList rbacv1.ClusterRoleBindingList
	if err := r.List(ctx, &crbList); err != nil {
		return nil, err
	}

	events := make([]ViolationEvent, 0)
	for i := range crbList.Items {
		crb := &crbList.Items[i]
		// Skip system ClusterRoles — these legitimately need cluster scope.
		if strings.HasPrefix(crb.RoleRef.Name, "system:") {
			continue
		}
		for _, sub := range crb.Subjects {
			// Skip system service accounts (kube-system namespace).
			if sub.Kind == rbacv1.ServiceAccountKind && sub.Namespace == metav1NamespaceKubeSystem {
				continue
			}
			// Skip system users and groups (names starting with "system:").
			if strings.HasPrefix(sub.Name, "system:") {
				continue
			}
			event, err := newViolationEvent(
				"RBAC-006",
				crb.Name,
				sub.Namespace,
				"LOW",
				crb,
				"Consider replacing this ClusterRoleBinding with a namespaced Role and RoleBinding scoped to the relevant namespace.",
			)
			if err != nil {
				return nil, err
			}
			// DEFENSE NOTE: Populate SubjectName/SubjectKind for per-subject deduplication,
			// consistent with RBAC-003. A ClusterRoleBinding with N non-system subjects
			// produces N distinct ViolationKeys so each subject gets an independent
			// deduplication key and audit trail entry.
			event.SubjectName = sub.Name
			event.SubjectKind = sub.Kind
			events = append(events, event)
			// Removed: break — emit one event per qualifying subject, not one per binding.
		}
	}
	return events, nil
}

// rbac003Risk assigns HIGH vs CRITICAL per docs/remediation-model.md (User treated as higher risk / "external").
func rbac003Risk(sub rbacv1.Subject) string {
	switch sub.Kind {
	case rbacv1.UserKind:
		return "CRITICAL"
	default:
		return "HIGH"
	}
}

func subjectNamespaceForLog(sub rbacv1.Subject) string {
	if sub.Namespace != "" {
		return sub.Namespace
	}
	// Group and User subjects have no namespace; log empty string for a stable schema.
	return ""
}

// subjectMatchesExclusion interprets patterns from the CRD:
//   - "system:masters" → Group or User exact name match
//   - "kube-system/*" → any ServiceAccount in namespace kube-system
//   - "kube-system/default" → specific ServiceAccount
//
// DEFENSE NOTE: Pattern semantics must match what the operator documents; glob is limited
// to namespace/* for service accounts to avoid guessing ambiguous short patterns.
func subjectMatchesExclusion(sub rbacv1.Subject, patterns []string) bool {
	for _, p := range patterns {
		if patternMatchesSubject(sub, strings.TrimSpace(p)) {
			return true
		}
	}
	return false
}

func patternMatchesSubject(sub rbacv1.Subject, pattern string) bool {
	if pattern == "" {
		return false
	}
	if strings.Contains(pattern, "/") {
		parts := strings.SplitN(pattern, "/", 2)
		ns, rest := parts[0], parts[1]
		if sub.Kind != rbacv1.ServiceAccountKind {
			return false
		}
		if sub.Namespace != ns {
			return false
		}
		if rest == "*" {
			return true
		}
		return sub.Name == rest
	}
	// No slash: apply to Group or User by exact name (covers "system:masters" as Group).
	if sub.Kind == rbacv1.GroupKind && sub.Name == pattern {
		return true
	}
	if sub.Kind == rbacv1.UserKind && sub.Name == pattern {
		return true
	}
	return false
}

// detectNamespacesWithoutNetworkPolicy implements NP-001 for namespaces not in exemptNamespaces.
func (r *ZeroTrustPolicyReconciler) detectNamespacesWithoutNetworkPolicy(ctx context.Context, policy *zerotrustv1alpha1.ZeroTrustPolicy) ([]ViolationEvent, error) {
	exempt := exemptionSet(policy.Spec.NetworkPolicy.ExemptNamespaces)

	var nsList corev1.NamespaceList
	if err := r.List(ctx, &nsList); err != nil {
		return nil, err
	}

	// DEFENSE NOTE: Single cluster-wide NetworkPolicyList instead of one List per
	// namespace. controller-runtime's informer cache serves this from memory (no
	// network round-trip). Consistent with the RBAC scalability refactor — O(1) API
	// calls regardless of namespace count, followed by an in-memory map lookup per
	// namespace in the loop below.
	var allNPList netv1.NetworkPolicyList
	if err := r.List(ctx, &allNPList); err != nil {
		return nil, err
	}
	npByNamespace := make(map[string][]netv1.NetworkPolicy, len(nsList.Items))
	for i := range allNPList.Items {
		np := &allNPList.Items[i]
		npByNamespace[np.Namespace] = append(npByNamespace[np.Namespace], *np)
	}

	events := make([]ViolationEvent, 0)
	for i := range nsList.Items {
		ns := &nsList.Items[i]
		if ns.Status.Phase != corev1.NamespaceActive {
			continue
		}
		if _, skip := exempt[ns.Name]; skip {
			continue
		}
		if !hasDefaultDenyIngress(npByNamespace[ns.Name]) {
			risk, err := r.np001Risk(ctx, ns.Name)
			if err != nil {
				return nil, err
			}
			event, err := newViolationEvent(
				"NP-001",
				ns.Name,
				ns.Name,
				risk,
				ns,
				"Apply a default-deny ingress NetworkPolicy in this namespace unless explicitly exempted.",
			)
			if err != nil {
				return nil, err
			}
			events = append(events, event)
		}
	}
	return events, nil
}

// detectNamespacesWithoutEgressPolicy implements NP-002: namespaces lacking a
// default-deny egress NetworkPolicy when requireDefaultDenyEgress is enabled.
//
// DEFENSE NOTE: Default-deny egress is the egress counterpart to NP-001.
// Without it, any compromised pod can freely exfiltrate data to external services.
// NP-002 is detection-only (no autofix) because the safe egress rules for a
// namespace depend on its workload — the operator must define them explicitly.
func (r *ZeroTrustPolicyReconciler) detectNamespacesWithoutEgressPolicy(ctx context.Context, policy *zerotrustv1alpha1.ZeroTrustPolicy) ([]ViolationEvent, error) {
	exempt := exemptionSet(policy.Spec.NetworkPolicy.ExemptNamespaces)

	var nsList corev1.NamespaceList
	if err := r.List(ctx, &nsList); err != nil {
		return nil, err
	}

	// DEFENSE NOTE: Same O(1) cluster-wide List pattern as detectNamespacesWithoutNetworkPolicy.
	// Avoids per-namespace List calls inside the loop.
	var allNPList netv1.NetworkPolicyList
	if err := r.List(ctx, &allNPList); err != nil {
		return nil, err
	}
	npByNamespace := make(map[string][]netv1.NetworkPolicy, len(nsList.Items))
	for i := range allNPList.Items {
		np := &allNPList.Items[i]
		npByNamespace[np.Namespace] = append(npByNamespace[np.Namespace], *np)
	}

	events := make([]ViolationEvent, 0)
	for i := range nsList.Items {
		ns := &nsList.Items[i]
		if ns.Status.Phase != corev1.NamespaceActive {
			continue
		}
		if _, skip := exempt[ns.Name]; skip {
			continue
		}
		if !hasDefaultDenyEgress(npByNamespace[ns.Name]) {
			risk := np002Risk(ns.Name)
			event, err := newViolationEvent(
				"NP-002",
				ns.Name,
				ns.Name,
				risk,
				ns,
				"Apply a default-deny egress NetworkPolicy in this namespace unless explicitly exempted.",
			)
			if err != nil {
				return nil, err
			}
			events = append(events, event)
		}
	}
	return events, nil
}

// hasDefaultDenyEgress returns true if policies contains a default-deny egress policy.
// Criteria mirror hasDefaultDenyIngress but check Egress instead of Ingress.
func hasDefaultDenyEgress(policies []netv1.NetworkPolicy) bool {
	for _, pol := range policies {
		// Criterion 1: podSelector must be empty — selects all pods.
		if len(pol.Spec.PodSelector.MatchLabels) != 0 || len(pol.Spec.PodSelector.MatchExpressions) != 0 {
			continue
		}
		// Criterion 2: policyTypes must include Egress (explicit) or both Ingress+Egress
		// must be absent (implicit full isolation). An empty policyTypes with no egress
		// rules defaults to ingress-only isolation per Kubernetes docs, so we require
		// explicit Egress here.
		hasEgressType := slices.Contains(pol.Spec.PolicyTypes, netv1.PolicyTypeEgress)
		if !hasEgressType {
			continue
		}
		// Criterion 3: egress rules must be absent or empty — zero allowed egress traffic.
		if len(pol.Spec.Egress) == 0 {
			return true
		}
	}
	return false
}

// np002Risk follows the same pattern as np001Risk: kube-system = CRITICAL, others = HIGH.
// NP-002 is detection-only; no autofix path exists. Risk drives escalation logging only.
//
// DEFENSE NOTE: NP-002 is always HIGH for standard namespaces (not LOW like NP-001)
// because unrestricted egress allows data exfiltration regardless of whether any pods
// are currently running — the risk is the policy gap, not the current workload state.
func np002Risk(namespace string) string {
	if namespace == metav1NamespaceKubeSystem {
		return "CRITICAL"
	}
	return "HIGH"
}

// hasDefaultDenyIngress returns true if policies contains at least one NetworkPolicy that
// acts as a proper default-deny ingress rule. All three criteria must be met:
//  1. spec.podSelector is empty — selects every pod in the namespace.
//  2. spec.policyTypes contains "Ingress" — the policy applies to inbound traffic.
//  3. spec.ingress is nil or empty — no ingress traffic is permitted.
func hasDefaultDenyIngress(policies []netv1.NetworkPolicy) bool {
	for _, pol := range policies {
		// Criterion 1: podSelector must be empty (no label filters — selects all pods).
		if len(pol.Spec.PodSelector.MatchLabels) != 0 || len(pol.Spec.PodSelector.MatchExpressions) != 0 {
			continue
		}
		// Criterion 2: policyTypes must include Ingress (explicit) OR be empty (implicit).
		// Kubernetes docs state: when policyTypes is omitted and the policy has no ingress
		// rules, the policy is treated as a default-deny ingress policy by the network plugin.
		// DEFENSE NOTE: Older manifests commonly omit policyTypes. Requiring explicit
		// declaration causes false-positive NP-001 violations for already-compliant namespaces,
		// producing redundant remediation writes every 30 seconds.
		hasIngressType := false
		if len(pol.Spec.PolicyTypes) == 0 {
			// Implicit ingress isolation: omitted policyTypes + empty ingress rules = default-deny ingress.
			hasIngressType = true
		} else {
			hasIngressType = slices.Contains(pol.Spec.PolicyTypes, netv1.PolicyTypeIngress)
		}
		if !hasIngressType {
			continue
		}
		// Criterion 3: ingress rules must be absent or empty — zero allowed ingress traffic.
		if len(pol.Spec.Ingress) == 0 {
			return true
		}
	}
	return false
}

func exemptionSet(names []string) map[string]struct{} {
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[strings.TrimSpace(n)] = struct{}{}
	}
	return out
}

// np001Risk returns NP-001 risk level following docs/remediation-model.md:
//
//	kube-system                           → CRITICAL (never auto-remediated)
//	namespace with Running or Pending pods → HIGH (escalate for human review)
//	empty namespace                        → LOW (safe to auto-remediate)
//
// DEFENSE NOTE: A namespace with live workloads must NOT be silently auto-remediated
// with a default-deny policy — this would block all new ingress connections without
// operator sign-off. Only empty namespaces are safe to auto-fix.
func (r *ZeroTrustPolicyReconciler) np001Risk(ctx context.Context, namespace string) (string, error) {
	if namespace == metav1NamespaceKubeSystem {
		return "CRITICAL", nil
	}
	var podList corev1.PodList
	if err := r.List(ctx, &podList, client.InNamespace(namespace)); err != nil {
		return "", err
	}
	for i := range podList.Items {
		phase := podList.Items[i].Status.Phase
		if phase == corev1.PodRunning || phase == corev1.PodPending {
			return "HIGH", nil
		}
	}
	return "LOW", nil
}

const metav1NamespaceKubeSystem = "kube-system"

func boolPtrVal(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

func stringSliceContains(slice []string, want string) bool {
	return slices.Contains(slice, want)
}

func newViolationEvent(
	violationType, resourceName, namespace, riskLevel string,
	resourceObj any,
	suggestedRemediation string,
) (ViolationEvent, error) {
	snapshot, err := json.Marshal(resourceObj)
	if err != nil {
		return ViolationEvent{}, err
	}
	// DEFENSE NOTE: ResourceSnapshot is captured at detection-time so remediation has a
	// before-state payload available before any write operation is introduced in Phase 2.
	return ViolationEvent{
		ViolationType:        violationType,
		ResourceName:         resourceName,
		Namespace:            namespace,
		RiskLevel:            riskLevel,
		DetectedAt:           time.Now().UTC(),
		ResourceSnapshot:     string(snapshot),
		SuggestedRemediation: suggestedRemediation,
	}, nil
}
