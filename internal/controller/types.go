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

import "time"

// ViolationKey uniquely identifies a persistent violation for deduplication and metrics.
type ViolationKey struct {
	ViolationType string
	ResourceName  string
	Namespace     string
	// SubjectName and SubjectKind are populated for RBAC-003 violations only.
	// They allow deduplication to track each offending subject independently,
	// preventing multiple subjects in the same binding from collapsing into one key.
	// DEFENSE NOTE: A ClusterRoleBinding with N non-whitelisted subjects produces N
	// distinct violation keys. Without these fields, only the first subject survives
	// in seenViolations after the first cycle — the rest are silently suppressed.
	SubjectName string
	SubjectKind string
}

// ViolationEvent is the detector output consumed by later remediation stages.
type ViolationEvent struct {
	ViolationType string
	ResourceName  string
	Namespace     string
	// DEFENSE NOTE: Allowed values are LOW, HIGH, or CRITICAL per docs/remediation-model.md.
	RiskLevel  string
	DetectedAt time.Time
	// ResourceSnapshot is the serialized JSON of the resource at detection time.
	ResourceSnapshot     string
	SuggestedRemediation string
	// SubjectName and SubjectKind are populated for RBAC-003 violations only.
	SubjectName string
	SubjectKind string
}
