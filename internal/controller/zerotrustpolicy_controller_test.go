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
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
							DenyWildcardVerbs:     &t,
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
							Mode:       zerotrustv1alpha1.RemediationModeDryrun,
							RateLimit:  &rate,
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
	})
})
