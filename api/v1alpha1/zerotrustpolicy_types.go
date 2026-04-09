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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.
// Schema follows docs/architecture.md "Policy Specification Schema (CRD Design)".

// DenyClusterAdminBindingConfig configures which subjects are allowed to hold cluster-admin.
// Used when denyClusterAdminBinding is true; subjects matching excludeServiceAccounts are permitted.
type DenyClusterAdminBindingConfig struct {
	// ExcludeServiceAccounts lists service account patterns allowed to hold cluster-admin.
	// Examples: "system:masters", "kube-system/*" (namespace/name pattern).
	// +optional
	ExcludeServiceAccounts []string `json:"excludeServiceAccounts,omitempty"`
}

// RBACSpec defines Zero Trust rules for RBAC (ClusterRoles, Roles, Bindings).
type RBACSpec struct {
	// DenyWildcardVerbs, when true, forbids any ClusterRole/Role with verbs: ["*"] or resources: ["*"].
	// +optional
	DenyWildcardVerbs *bool `json:"denyWildcardVerbs,omitempty"`

	// DenyClusterAdminBinding configures enforcement of "no cluster-admin for non-system accounts".
	// When set, only excludeServiceAccounts are allowed to be bound to cluster-admin.
	// +optional
	DenyClusterAdminBinding *DenyClusterAdminBindingConfig `json:"denyClusterAdminBinding,omitempty"`

	// RequireNamespacedRoles, when true, encourages namespaced Roles over cluster-scoped ClusterRoles where possible.
	// +optional
	RequireNamespacedRoles *bool `json:"requireNamespacedRoles,omitempty"`
}

// NetworkPolicySpec defines Zero Trust rules for NetworkPolicies (default-deny, exemptions).
type NetworkPolicySpec struct {
	// RequireDefaultDenyIngress, when true, every namespace must have a default-deny-ingress NetworkPolicy.
	// +optional
	RequireDefaultDenyIngress *bool `json:"requireDefaultDenyIngress,omitempty"`

	// RequireDefaultDenyEgress, when true, every namespace must have a default-deny-egress NetworkPolicy.
	// +optional
	RequireDefaultDenyEgress *bool `json:"requireDefaultDenyEgress,omitempty"`

	// ExemptNamespaces are not required to have default-deny policies (e.g. kube-system, monitoring).
	// +optional
	ExemptNamespaces []string `json:"exemptNamespaces,omitempty"`
}

// RemediationMode is the mode for applying remediations (auto, dryrun, or manual).
// +kubebuilder:validation:Enum=auto;dryrun;manual
type RemediationMode string

const (
	// RemediationModeAuto applies low-risk fixes automatically (within rate limit).
	RemediationModeAuto RemediationMode = "auto"
	// RemediationModeDryrun logs what would be done without making API writes.
	RemediationModeDryrun RemediationMode = "dryrun"
	// RemediationModeManual disables auto-remediation; only escalation/audit.
	RemediationModeManual RemediationMode = "manual"
)

// RemediationSpec configures how violations are remediated (mode, rate limit, approval requirements).
type RemediationSpec struct {
	// Mode controls whether remediations are applied automatically, only logged (dryrun), or disabled (manual).
	// +kubebuilder:default=auto
	// +optional
	Mode RemediationMode `json:"mode,omitempty"`

	// RateLimit is the maximum number of remediations applied per reconcile cycle
	// (default interval: 30 seconds). For example, 5 means at most 5 auto-remediations
	// per 30-second cycle; excess violations are escalated for human review.
	// +kubebuilder:default=5
	// +kubebuilder:validation:Minimum=1
	// +optional
	RateLimit *int32 `json:"rateLimit,omitempty"`

	// RequireApprovalFor lists violation types that must always be escalated (never auto-remediated).
	// Example: "ClusterAdminBinding".
	// +optional
	RequireApprovalFor []string `json:"requireApprovalFor,omitempty"`
}

// ZeroTrustPolicySpec defines the desired state of ZeroTrustPolicy.
// It is the formal Zero Trust baseline loaded by the controller (see docs/architecture.md).
type ZeroTrustPolicySpec struct {
	// RBAC holds rules for RBAC auditing (wildcards, cluster-admin binding, namespaced roles).
	// +optional
	RBAC *RBACSpec `json:"rbac,omitempty"`

	// NetworkPolicy holds rules for NetworkPolicy auditing (default-deny, exempt namespaces).
	// +optional
	NetworkPolicy *NetworkPolicySpec `json:"networkPolicy,omitempty"`

	// Remediation configures remediation behaviour: mode (auto/dryrun/manual), rate limit, and approval list.
	// +optional
	Remediation *RemediationSpec `json:"remediation,omitempty"`
}

// ZeroTrustPolicyStatus defines the observed state of ZeroTrustPolicy.
type ZeroTrustPolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// conditions represent the current state of the ZeroTrustPolicy resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Remediation",type=string,JSONPath=`.spec.remediation.mode`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ZeroTrustPolicy is the Schema for the zerotrustpolicies API (Zero Trust baseline for the cluster).
type ZeroTrustPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of ZeroTrustPolicy
	// +required
	Spec ZeroTrustPolicySpec `json:"spec"`

	// status defines the observed state of ZeroTrustPolicy
	// +optional
	Status ZeroTrustPolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ZeroTrustPolicyList contains a list of ZeroTrustPolicy
type ZeroTrustPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ZeroTrustPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ZeroTrustPolicy{}, &ZeroTrustPolicyList{})
}
