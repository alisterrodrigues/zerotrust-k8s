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

	"github.com/rs/zerolog/log"
)

// applyRemediation executes AUTO_FIX actions.
// DEFENSE NOTE: This remains a stub in Phase 2 by design so decision/audit behavior can be
// validated before introducing Kubernetes write operations.
func (r *ZeroTrustPolicyReconciler) applyRemediation(ctx context.Context, event ViolationEvent) error {
	_ = ctx
	log.Info().
		Str("violationType", event.ViolationType).
		Str("resourceName", event.ResourceName).
		Str("namespace", event.Namespace).
		Msg("AUTO_FIX stub called")
	return nil
}
