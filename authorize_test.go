/*

Copyright 2016 All rights reserved.
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

package main

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"k8s.io/kubernetes/pkg/apis/authorization/v1beta1"

	"github.com/stretchr/testify/assert"
	"k8s.io/kubernetes/pkg/api/unversioned"
)

var (
	failedAuthzRequest = v1beta1.SubjectAccessReview{
		TypeMeta: unversioned.TypeMeta{
			Kind:       "SubjectAccessReview",
			APIVersion: "authorization.k8s.io/v1beta1",
		},
		Status: v1beta1.SubjectAccessReviewStatus{
			Allowed: false,
			Reason:  "No policy matched.",
		},
	}

	successAuthzResponse = v1beta1.SubjectAccessReview{
		TypeMeta: unversioned.TypeMeta{
			Kind:       "SubjectAccessReview",
			APIVersion: "authorization.k8s.io/v1beta1",
		},
		Status: v1beta1.SubjectAccessReviewStatus{
			Allowed: true,
		},
	}
)

func TestAuthorization(t *testing.T) {
	s := newTestService(t)
	defer s.Close()

	cs := []struct {
		Review   v1beta1.SubjectAccessReview
		Expected v1beta1.SubjectAccessReview
	}{
		{
			Review: v1beta1.SubjectAccessReview{
				TypeMeta: unversioned.TypeMeta{
					Kind:       "SubjectAccessReview",
					APIVersion: "authorization.k8s.io/v1beta1",
				},
				Spec: v1beta1.SubjectAccessReviewSpec{
					NonResourceAttributes: &v1beta1.NonResourceAttributes{
						Path: "/v1/api",
						Verb: "get",
					},
				},
			},
			Expected: successAuthzResponse,
		},
		{
			Review: v1beta1.SubjectAccessReview{
				TypeMeta: unversioned.TypeMeta{
					Kind:       "SubjectAccessReview",
					APIVersion: "authorization.k8s.io/v1beta1",
				},
				Spec: v1beta1.SubjectAccessReviewSpec{
					User:   "admin",
					Groups: []string{},
					ResourceAttributes: &v1beta1.ResourceAttributes{
						Resource:  "pods",
						Namespace: "default",
						Verb:      "get",
					},
				},
			},
			Expected: successAuthzResponse,
		},
		{
			Review: v1beta1.SubjectAccessReview{
				TypeMeta: unversioned.TypeMeta{
					Kind:       "SubjectAccessReview",
					APIVersion: "authorization.k8s.io/v1beta1",
				},
				Spec: v1beta1.SubjectAccessReviewSpec{
					User:   "user1",
					Groups: []string{},
					ResourceAttributes: &v1beta1.ResourceAttributes{
						Resource:  "pods",
						Namespace: "not_allowed",
						Verb:      "get",
					},
				},
			},
			Expected: failedAuthzRequest,
		},
		{
			Review: v1beta1.SubjectAccessReview{
				TypeMeta: unversioned.TypeMeta{
					Kind:       "SubjectAccessReview",
					APIVersion: "authorization.k8s.io/v1beta1",
				},
				Spec: v1beta1.SubjectAccessReviewSpec{
					User:   "user3",
					Groups: []string{"group3"},
					ResourceAttributes: &v1beta1.ResourceAttributes{
						Resource:  "pods",
						Namespace: "sip-demo",
						Verb:      "get",
					},
				},
			},
			Expected: successAuthzResponse,
		},
	}
	for _, x := range cs {
		status, err := makeTestAuthzRequest(s.URL(), x.Review)
		if !assert.NoError(t, err) {
			t.Failed()
		}
		assert.Equal(t, x.Expected, status)
	}
}

func TestAuthorizationFileChange(t *testing.T) {
	s := newTestService(t)
	defer s.Close()

	request := v1beta1.SubjectAccessReview{
		Spec: v1beta1.SubjectAccessReviewSpec{
			User:   "admin_user",
			Groups: []string{},
			ResourceAttributes: &v1beta1.ResourceAttributes{
				Resource:  "pods",
				Namespace: "default",
				Verb:      "get",
			},
		},
	}

	// step: make a failed attempt
	status, err := makeTestAuthzRequest(s.URL(), request)
	if !assert.NoError(t, err) {
		t.Failed()
	}
	assert.Equal(t, failedAuthzRequest, status)

	// step: update the auth file
	updateTestFile(t, s.s.cfg.authFile, `{"apiVersion":"abac.authorization.kubernetes.io/v1beta1","kind":"Policy","spec":{ "user":"admin_user", "namespace": "default", "resource": "*" }}`)
	time.Sleep(800 * time.Millisecond)

	status, err = makeTestAuthzRequest(s.URL(), request)
	if !assert.NoError(t, err) {
		t.Failed()
	}
	assert.Equal(t, successAuthzResponse, status)
}

func makeTestAuthzRequest(url string, review v1beta1.SubjectAccessReview) (v1beta1.SubjectAccessReview, error) {
	var status v1beta1.SubjectAccessReview

	res, err := hc.R().
		SetHeader("Content-Type", "application/json").
		SetBody(review).
		SetResult(&status).
		Post(url + "/authorize/policy")
	if err != nil {
		return status, err
	}
	if res.StatusCode() != http.StatusOK {
		return status, errors.New("invalid response from authz api")
	}

	return status, nil
}
