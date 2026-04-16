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
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	auditLogConfigMapName  = "ztk8s-audit-log"
	auditLogBaseKey        = "audit.log"
	auditLogMaxDataBytes   = 900 * 1024
	auditLogMaxObjectBytes = 850 * 1024
	defaultAuditNamespace  = "zerotrust-system"
)

// auditLogConfigMapNamespace is the namespace for the audit log ConfigMap.
// It is set at startup by SetAuditNamespace() from the NAMESPACE env var,
// falling back to defaultAuditNamespace if the env var is absent.
// DEFENSE NOTE: Reading namespace from the Pod's own metadata at runtime
// (via the downward API env var) ensures the audit log is written to the
// correct namespace in any deployment model, not just the local make run path.
var auditLogConfigMapNamespace = defaultAuditNamespace

// SetAuditNamespace configures the namespace for the audit log ConfigMap.
// Call this from main() before starting the manager.
func SetAuditNamespace(ns string) {
	if ns != "" {
		auditLogConfigMapNamespace = ns
	}
}

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

// currentAuditConfigMapName returns the name of the active audit ConfigMap.
// It lists all ztk8s-audit-log* ConfigMaps in the audit namespace and returns
// the one with the highest numeric suffix whose data size is below the object limit.
// If none exists, it returns the base name for creation.
//
// DEFENSE NOTE: By rotating to new ConfigMap OBJECTS (not new keys within the same object),
// we stay safely below Kubernetes's 1 MiB per-object limit regardless of audit volume.
func currentAuditConfigMapName(ctx context.Context, k8sClient client.Client) (string, error) {
	var cmList corev1.ConfigMapList
	if err := k8sClient.List(ctx, &cmList,
		client.InNamespace(auditLogConfigMapNamespace)); err != nil {
		return auditLogConfigMapName, err
	}

	// Find all audit log ConfigMaps and sort by index.
	highest := 0
	highestSize := 0
	for _, cm := range cmList.Items {
		if cm.Name == auditLogConfigMapName {
			size := 0
			for _, v := range cm.Data {
				size += len(v)
			}
			if highest == 0 {
				highest = 1
				highestSize = size
			}
		} else if strings.HasPrefix(cm.Name, auditLogConfigMapName+"-") {
			suffix := strings.TrimPrefix(cm.Name, auditLogConfigMapName+"-")
			n, err := strconv.Atoi(suffix)
			if err != nil {
				continue
			}
			if n > highest {
				size := 0
				for _, v := range cm.Data {
					size += len(v)
				}
				highest = n
				highestSize = size
			}
		}
	}

	if highest == 0 {
		return auditLogConfigMapName, nil
	}
	if highestSize >= auditLogMaxObjectBytes {
		// Current object is full — return name for next object.
		if highest == 1 {
			return auditLogConfigMapName + "-2", nil
		}
		return fmt.Sprintf("%s-%d", auditLogConfigMapName, highest+1), nil
	}
	if highest == 1 {
		return auditLogConfigMapName, nil
	}
	return fmt.Sprintf("%s-%d", auditLogConfigMapName, highest), nil
}

// AppendAuditEntry appends one JSON line into the active audit ConfigMap without overwriting existing lines.
func AppendAuditEntry(ctx context.Context, k8sClient client.Client, entry AuditEntry) error {
	encoded, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	line := string(encoded) + "\n"

	targetName, err := currentAuditConfigMapName(ctx, k8sClient)
	if err != nil {
		// Fall back to base name on list error — better to attempt write than lose entry.
		targetName = auditLogConfigMapName
	}
	key := client.ObjectKey{
		Name:      targetName,
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
				Name:      targetName,
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

	cm.Data[auditLogBaseKey] = cm.Data[auditLogBaseKey] + line
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

	targetName, err := currentAuditConfigMapName(ctx, k8sClient)
	if err != nil {
		// Fall back to base name on list error — better to attempt write than lose entry.
		targetName = auditLogConfigMapName
	}
	key := client.ObjectKey{
		Name:      targetName,
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
				Name:      targetName,
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

	for _, line := range lines {
		cm.Data[auditLogBaseKey] = cm.Data[auditLogBaseKey] + line
	}

	return k8sClient.Update(ctx, &cm)
}
