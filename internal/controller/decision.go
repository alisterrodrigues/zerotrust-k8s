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
	"strings"

	zerotrustv1alpha1 "github.com/capstone/zerotrust-k8s/api/v1alpha1"
)

const (
	DecisionActionAutoFix  = "AUTO_FIX"
	DecisionActionEscalate = "ESCALATE"
	DecisionActionDryRun   = "DRY_RUN_LOG"
	DecisionActionSkip     = "SKIP"
)

type ZeroTrustPolicySpec = zerotrustv1alpha1.ZeroTrustPolicySpec

// RemediationDecision is the action selected from the matrix for one violation.
type RemediationDecision struct {
	Action          string
	Reason          string
	SuggestedAction string
}

// Decide applies docs/remediation-model.md matrix with mode overrides.
func Decide(event ViolationEvent, policy ZeroTrustPolicySpec) RemediationDecision {
	decision := decisionFromMatrix(event)
	mode := remediationModeFromSpec(policy)

	// DEFENSE NOTE: RequireApprovalFor is a CRD-level safety control that lets cluster operators
	// declare certain violation classes as always requiring human sign-off, regardless of risk level.
	// This prevents automated remediation of politically sensitive or high-impact resource types
	// even when the risk matrix would normally allow AUTO_FIX. It is checked before mode overrides
	// so that manual approval intent cannot be accidentally overridden by mode=auto.
	if policy.Remediation != nil && len(policy.Remediation.RequireApprovalFor) > 0 {
		if approvalRequired(event.ViolationType, policy.Remediation.RequireApprovalFor) {
			return RemediationDecision{
				Action:          DecisionActionEscalate,
				Reason:          "violation type in requireApprovalFor list — human review required",
				SuggestedAction: decision.SuggestedAction,
			}
		}
	}

	// DEFENSE NOTE: Manual and dryrun are explicit safety controls. They intentionally override
	// normal matrix outcomes to reduce blast radius during validation or human-only review phases.
	if mode == "manual" {
		return RemediationDecision{
			Action:          DecisionActionEscalate,
			Reason:          "remediation.mode=manual forces human review",
			SuggestedAction: decision.SuggestedAction,
		}
	}
	if mode == "dryrun" && decision.Action == DecisionActionAutoFix {
		return RemediationDecision{
			Action:          DecisionActionDryRun,
			Reason:          "remediation.mode=dryrun converts AUTO_FIX into DRY_RUN_LOG",
			SuggestedAction: decision.SuggestedAction,
		}
	}
	return decision
}

func decisionFromMatrix(event ViolationEvent) RemediationDecision {
	switch event.ViolationType {
	case "NP-001":
		switch event.RiskLevel {
		case "LOW":
			return RemediationDecision{
				Action:          DecisionActionAutoFix,
				Reason:          "NP-001 LOW: non-system namespace without NetworkPolicy is eligible for additive default-deny fix",
				SuggestedAction: "Apply a default-deny ingress NetworkPolicy in the namespace.",
			}
		case "HIGH":
			return RemediationDecision{
				Action:          DecisionActionEscalate,
				Reason:          "NP-001 HIGH: escalate for human review",
				SuggestedAction: "Review live workload impact and apply a safe default-deny policy with required allow-rules.",
			}
		case "CRITICAL":
			return RemediationDecision{
				Action:          DecisionActionSkip,
				Reason:          "NP-001 CRITICAL: skip auto action for protected/exempt critical namespace",
				SuggestedAction: "Review exemption and handle manually.",
			}
		}
	case "RBAC-001":
		switch event.RiskLevel {
		case "LOW":
			return RemediationDecision{
				Action:          DecisionActionAutoFix,
				Reason:          "RBAC-001 LOW + no active bindings: eligible for wildcard-verb cleanup",
				SuggestedAction: "Remove wildcard verb from the role and replace with explicit least-privilege verbs.",
			}
		case "HIGH":
			return RemediationDecision{
				Action:          DecisionActionEscalate,
				Reason:          "RBAC-001 HIGH: active bindings exist, escalate",
				SuggestedAction: "Review impacted subjects and patch role verbs safely.",
			}
		case "CRITICAL":
			return RemediationDecision{
				Action:          DecisionActionEscalate,
				Reason:          "RBAC-001 CRITICAL: system role impact, escalate immediately",
				SuggestedAction: "Perform urgent security review and patch role in controlled change window.",
			}
		}
	case "RBAC-002":
		return RemediationDecision{
			Action:          DecisionActionEscalate,
			Reason:          "RBAC-002 any risk: always escalate per matrix",
			SuggestedAction: "Scope wildcard resources to explicit resources.",
		}
	case "RBAC-003":
		return RemediationDecision{
			Action:          DecisionActionEscalate,
			Reason:          "RBAC-003 any risk: always escalate per matrix",
			SuggestedAction: "Revoke or strictly scope non-whitelisted cluster-admin bindings.",
		}
	}

	return RemediationDecision{
		Action:          DecisionActionEscalate,
		Reason:          "unmapped violation type defaults to ESCALATE for safety",
		SuggestedAction: event.SuggestedRemediation,
	}
}

func remediationModeFromSpec(spec ZeroTrustPolicySpec) string {
	if spec.Remediation == nil {
		return "auto"
	}
	mode := string(spec.Remediation.Mode)
	if mode == "" {
		return "auto"
	}
	return mode
}

// approvalRequired returns true if violationType matches any entry in requireApprovalFor.
// Matching is case-insensitive. Human-readable aliases in the CRD are resolved to canonical
// violation type codes before comparison.
func approvalRequired(violationType string, requireApprovalFor []string) bool {
	// aliasMap translates the human-friendly names accepted by the CRD field to their canonical
	// violation type codes. Operators write e.g. "ClusterAdminBinding" in their policy YAML
	// rather than memorising "RBAC-003".
	aliasMap := map[string]string{
		"clusteradminbinding":  "RBAC-003",
		"wildcardverbs":        "RBAC-001",
		"wildcardresources":    "RBAC-002",
		"missingnetworkpolicy": "NP-001",
	}
	vtLower := strings.ToLower(violationType)
	for _, entry := range requireApprovalFor {
		entryLower := strings.ToLower(strings.TrimSpace(entry))
		// Direct case-insensitive match on the violation type code itself (e.g. "RBAC-001").
		if entryLower == vtLower {
			return true
		}
		// Alias match: resolve the alias to a canonical code and compare.
		if canonical, ok := aliasMap[entryLower]; ok {
			if strings.ToLower(canonical) == vtLower {
				return true
			}
		}
	}
	return false
}
