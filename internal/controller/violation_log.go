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
	"os"
	"time"

	"github.com/rs/zerolog"
)

//nolint:gochecknoinits // Global zerolog settings must run before the first violation line.
func init() {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.TimestampFieldName = "timestamp"
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
}

// violationLog emits one JSON object per line to stdout for security/SIEM ingestion.
// It is separate from controller-runtime’s zap logger so violation telemetry stays
// consistent regardless of the framework log level.
var violationLog = zerolog.New(os.Stdout).With().Timestamp().Logger()

// logViolation writes a single structured JSON line with the required fields.
func logViolation(violationType, resourceName, namespace, riskLevel string) {
	// DEFENSE NOTE: Keep this schema stable—evaluators and log pipelines key off these names.
	violationLog.Info().
		Str("violationType", violationType).
		Str("resourceName", resourceName).
		Str("namespace", namespace).
		Str("riskLevel", riskLevel).
		Msg("violation_detected")
}
