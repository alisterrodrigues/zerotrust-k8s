/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	zerotrustv1alpha1 "github.com/capstone/zerotrust-k8s/api/v1alpha1"
)

var _ = Describe("ZeroTrustPolicy Controller", func() {
	Context("When reconciling the cluster baseline", func() {
		ctx := context.Background()

		// ZeroTrustPolicy is cluster-scoped; NamespacedName carries name only.
		baselineKey := types.NamespacedName{Name: clusterBaselineName}
		baseline := &zerotrustv1alpha1.ZeroTrustPolicy{}

		BeforeEach(func() {
			By("creating the cluster-baseline ZeroTrustPolicy")
			err := k8sClient.Get(ctx, baselineKey, baseline)
			if err != nil && errors.IsNotFound(err) {
				t := true
				f := false
				rate := int32(5)
				resource := &zerotrustv1alpha1.ZeroTrustPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: clusterBaselineName},
					Spec: zerotrustv1alpha1.ZeroTrustPolicySpec{
						RBAC: &zerotrustv1alpha1.RBACSpec{
							DenyWildcardVerbs: &t,
							DenyClusterAdminBinding: &zerotrustv1alpha1.DenyClusterAdminBindingConfig{
								ExcludeServiceAccounts: []string{"system:masters", "kube-system/*"},
							},
						},
						NetworkPolicy: &zerotrustv1alpha1.NetworkPolicySpec{
							RequireDefaultDenyIngress: &t,
							RequireDefaultDenyEgress:  &f,
							ExemptNamespaces:          []string{"kube-system", "kube-public", "kube-node-lease"},
						},
						Remediation: &zerotrustv1alpha1.RemediationSpec{
							Mode:               zerotrustv1alpha1.RemediationModeDryrun,
							RateLimit:          &rate,
							RequireApprovalFor: []string{"ClusterAdminBinding"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			By("Cleaning up the cluster-baseline ZeroTrustPolicy")
			res := &zerotrustv1alpha1.ZeroTrustPolicy{}
			err := k8sClient.Get(ctx, baselineKey, res)
			if err == nil {
				Expect(k8sClient.Delete(ctx, res)).To(Succeed())
			}
		})

		It("should successfully reconcile without error", func() {
			By("Running Reconcile for cluster-baseline")
			reconciler := &ZeroTrustPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: baselineKey})
			Expect(err).NotTo(HaveOccurred())
			Expect(res.RequeueAfter).To(Equal(auditRequeueInterval))
		})

		It("should detect RBAC-001 when a ClusterRole with wildcard verbs exists", func() {
			// DEFENSE NOTE: This test injects a ClusterRole with verbs: ["*"] and verifies
			// that runDetections returns at least one RBAC-001 violation event. It confirms
			// the detection pipeline fires end-to-end with a real envtest API server.
			By("creating a ClusterRole with wildcard verbs")
			wildcardRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-wildcard-verbs"},
				Rules: []rbacv1.PolicyRule{
					{Verbs: []string{"*"}, APIGroups: []string{""}, Resources: []string{"pods"}},
				},
			}
			Expect(k8sClient.Create(ctx, wildcardRole)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, wildcardRole)
			})

			By("loading the cluster-baseline policy")
			var policy zerotrustv1alpha1.ZeroTrustPolicy
			Expect(k8sClient.Get(ctx, baselineKey, &policy)).To(Succeed())

			By("running detections directly")
			reconciler := &ZeroTrustPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			events, err := reconciler.runDetections(ctx, &policy)
			Expect(err).NotTo(HaveOccurred())

			found := false
			for _, e := range events {
				if e.ViolationType == "RBAC-001" && e.ResourceName == "test-wildcard-verbs" {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "expected RBAC-001 violation for test-wildcard-verbs")
		})

		It("should detect NP-001 when a namespace has no default-deny NetworkPolicy", func() {
			// DEFENSE NOTE: This test creates a namespace with no NetworkPolicy and verifies
			// that runDetections returns an NP-001 violation for it. Confirms the NP detection
			// pipeline is wired correctly end-to-end with a real API server and namespace object.
			By("creating a namespace with no NetworkPolicy")
			testNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-no-netpol"},
			}
			Expect(k8sClient.Create(ctx, testNS)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, testNS)
			})

			By("loading the cluster-baseline policy")
			var policy zerotrustv1alpha1.ZeroTrustPolicy
			Expect(k8sClient.Get(ctx, baselineKey, &policy)).To(Succeed())

			By("running detections directly")
			reconciler := &ZeroTrustPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			events, err := reconciler.runDetections(ctx, &policy)
			Expect(err).NotTo(HaveOccurred())

			found := false
			for _, e := range events {
				if e.ViolationType == "NP-001" && e.ResourceName == "test-no-netpol" {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "expected NP-001 violation for test-no-netpol")
		})
	})
})
