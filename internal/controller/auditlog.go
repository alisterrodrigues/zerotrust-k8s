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
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	auditLogConfigMapName      = "ztk8s-audit-log"
	auditLogConfigMapNamespace = "zerotrust-system"
	auditLogBaseKey            = "audit.log"
	auditLogMaxDataBytes       = 900 * 1024
)

// AuditEntry is a single append-only audit record for remediation/escalation handling.
type AuditEntry struct {
	EntryID                string
	ViolationType          string
	RiskLevel              string
	ResourceName           string
	Namespace              string
	Action                 string
	Reason                 string
	PreRemediationSnapshot string
	SuggestedAction        string
	Timestamp              time.Time
}

// AppendAuditEntry appends one JSON line into ztk8s-audit-log ConfigMap without overwriting existing lines.
func AppendAuditEntry(ctx context.Context, k8sClient client.Client, entry AuditEntry) error {
	encoded, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	line := string(encoded) + "\n"
	key := client.ObjectKey{
		Name:      auditLogConfigMapName,
		Namespace: auditLogConfigMapNamespace,
	}

	var cm corev1.ConfigMap
	if err := k8sClient.Get(ctx, key, &cm); err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		// DEFENSE NOTE: Creating the ConfigMap lazily keeps bootstrap simple: no separate install step is
		// required before first remediation cycle writes an audit record.
		cm = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      auditLogConfigMapName,
				Namespace: auditLogConfigMapNamespace,
			},
			Data: map[string]string{
				auditLogBaseKey: line,
			},
		}
		return k8sClient.Create(ctx, &cm)
	}

	if cm.Data == nil {
		cm.Data = map[string]string{}
	}

	targetKey := nextAuditKey(cm.Data, len(line))
	cm.Data[targetKey] = cm.Data[targetKey] + line
	return k8sClient.Update(ctx, &cm)
}

// AppendAuditEntries writes all entries in a single ConfigMap Update,
// eliminating optimistic concurrency conflicts from per-entry writes.
//
// DEFENSE NOTE: Kubernetes uses resourceVersion for optimistic concurrency
// control. Every successful Update increments resourceVersion. If two
// goroutines both do Get then Update on the same object, the second Update
// will fail because its resourceVersion is now stale. By collecting all
// entries for a cycle into a slice and writing them in one batch, we
// guarantee at most one write per reconcile cycle regardless of how many
// violations were found. This is the standard Kubernetes controller pattern
// for high-frequency writes to a shared object.
func AppendAuditEntries(ctx context.Context, k8sClient client.Client, entries []AuditEntry) error {
	if len(entries) == 0 {
		return nil
	}

	// Marshal all entries into newline-delimited JSON lines first,
	// before touching the API server.
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		encoded, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		lines = append(lines, string(encoded)+"\n")
	}

	key := client.ObjectKey{
		Name:      auditLogConfigMapName,
		Namespace: auditLogConfigMapNamespace,
	}

	var cm corev1.ConfigMap
	if err := k8sClient.Get(ctx, key, &cm); err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		// ConfigMap doesn't exist yet — create it with all lines combined.
		combined := strings.Join(lines, "")
		cm = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      auditLogConfigMapName,
				Namespace: auditLogConfigMapNamespace,
			},
			Data: map[string]string{
				auditLogBaseKey: combined,
			},
		}
		return k8sClient.Create(ctx, &cm)
	}

	if cm.Data == nil {
		cm.Data = map[string]string{}
	}

	// Append each line, respecting the 900KB per-key limit with rollover.
	for _, line := range lines {
		targetKey := nextAuditKey(cm.Data, len(line))
		cm.Data[targetKey] = cm.Data[targetKey] + line
	}

	return k8sClient.Update(ctx, &cm)
}

func nextAuditKey(data map[string]string, newLineBytes int) string {
	if len(data) == 0 {
		return auditLogBaseKey
	}

	indices := make([]int, 0)
	for key := range data {
		idx, ok := parseAuditKeyIndex(key)
		if ok {
			indices = append(indices, idx)
		}
	}
	if len(indices) == 0 {
		return auditLogBaseKey
	}
	sort.Ints(indices)
	last := indices[len(indices)-1]
	lastKey := auditKeyForIndex(last)
	if len(data[lastKey])+newLineBytes <= auditLogMaxDataBytes {
		return lastKey
	}
	return auditKeyForIndex(last + 1)
}

func parseAuditKeyIndex(key string) (int, bool) {
	if key == auditLogBaseKey {
		return 1, true
	}
	if !strings.HasPrefix(key, auditLogBaseKey+".") {
		return 0, false
	}
	raw := strings.TrimPrefix(key, auditLogBaseKey+".")
	n, err := strconv.Atoi(raw)
	if err != nil || n < 2 {
		return 0, false
	}
	return n, true
}

func auditKeyForIndex(index int) string {
	if index <= 1 {
		return auditLogBaseKey
	}
	return fmt.Sprintf("%s.%d", auditLogBaseKey, index)
}
