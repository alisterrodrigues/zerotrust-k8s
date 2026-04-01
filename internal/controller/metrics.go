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
	"github.com/prometheus/client_golang/prometheus"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Prometheus metric names use snake_case; each matches the Phase 3 observability surface described
// in docs/architecture.md and the measurement themes in docs/evaluation-plan.md.

var (
	// ztk8sViolationsTotal counts every ViolationEvent emitted by detectors in a reconcile cycle.
	// DEFENSE NOTE: Maps to evaluation-plan “detection” workload and false-positive studies — you
	// correlate spikes in violations with test harness applies and compare against ground-truth scenarios.
	ztk8sViolationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ztk8s_violations_total",
			Help: "Total number of violations detected by the ZeroTrust controller",
		},
		[]string{"violation_type", "namespace", "risk_level"},
	)

	// ztk8sRemediationsTotal counts successful AUTO_FIX paths (actual remediation writes).
	// DEFENSE NOTE: Supports evaluation-plan “Remediation time” trials — count confirms how many
	// auto-remediations completed vs escalations when you run repeated NP-001 / RBAC-001-low experiments.
	ztk8sRemediationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ztk8s_remediations_total",
			Help: "Total number of violations auto-remediated by the ZeroTrust controller",
		},
		[]string{"violation_type", "namespace"},
	)

	// ztk8sEscalationsTotal counts human-review queue entries (audit append after ESCALATE decision).
	// DEFENSE NOTE: Tracks how much work would land on operators under manual/dryrun/rate-limit paths;
	// pairs with evaluation-plan escalation and safety (circuit breaker / rate limit) narratives.
	ztk8sEscalationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ztk8s_escalations_total",
			Help: "Total number of violations escalated for human review",
		},
		[]string{"violation_type", "namespace"},
	)

	// ztk8sCycleDurationSeconds observes full Reconcile() wall time per invocation.
	// DEFENSE NOTE: Maps to evaluation-plan “Performance overhead” and reconcile SLO checks — bucketed
	// latency shows whether audit+decision stays within expected bounds (e.g. ~30s tick vs slow API).
	ztk8sCycleDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "ztk8s_cycle_duration_seconds",
			Help:    "Duration of each ZeroTrust audit reconcile cycle in seconds",
			Buckets: []float64{0.1, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
	)
)

func init() {
	crmetrics.Registry.MustRegister(
		ztk8sViolationsTotal,
		ztk8sRemediationsTotal,
		ztk8sEscalationsTotal,
		ztk8sCycleDurationSeconds,
	)
}

// RecordViolation increments the violations counter for one detected event.
func RecordViolation(violationType, namespace, riskLevel string) {
	ztk8sViolationsTotal.WithLabelValues(violationType, namespace, riskLevel).Inc()
}

// RecordRemediation increments the auto-remediation counter after a successful fix.
func RecordRemediation(violationType, namespace string) {
	ztk8sRemediationsTotal.WithLabelValues(violationType, namespace).Inc()
}

// RecordEscalation increments the escalation counter after a successful escalation audit write.
func RecordEscalation(violationType, namespace string) {
	ztk8sEscalationsTotal.WithLabelValues(violationType, namespace).Inc()
}

// RecordCycleDuration observes reconcile duration in seconds.
func RecordCycleDuration(durationSeconds float64) {
	ztk8sCycleDurationSeconds.Observe(durationSeconds)
}
