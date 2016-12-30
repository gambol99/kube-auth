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
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/apis/authorization/v1beta1"
	"k8s.io/kubernetes/pkg/auth/authorizer"
	"k8s.io/kubernetes/pkg/auth/user"
)

type attributeWrapper struct {
	review *v1beta1.SubjectAccessReview
}

// authorize is responsible for authorizing a request via the abac file
func (s *service) authorize(review *v1beta1.SubjectAccessReview) (v1beta1.SubjectAccessReview, error) {
	s.RLock()
	defer s.RUnlock()

	var response = v1beta1.SubjectAccessReview{
		TypeMeta: unversioned.TypeMeta{
			Kind:       "SubjectAccessReview",
			APIVersion: "authorization.k8s.io/v1beta1",
		},
	}

	request := &authorizer.AttributesRecord{
		User: &user.DefaultInfo{
			Name:   review.Spec.User,
			Groups: review.Spec.Groups,
		},
	}
	if review.Spec.ResourceAttributes != nil {
		request.Verb = review.Spec.ResourceAttributes.Verb
		request.Namespace = review.Spec.ResourceAttributes.Namespace
		request.APIGroup = review.Spec.ResourceAttributes.Group
		request.APIVersion = review.Spec.ResourceAttributes.Version
		request.Resource = review.Spec.ResourceAttributes.Resource
		request.Subresource = review.Spec.ResourceAttributes.Subresource
		request.Name = review.Spec.ResourceAttributes.Name
	}
	if review.Spec.NonResourceAttributes != nil {
		request.Path = review.Spec.NonResourceAttributes.Path
		request.Verb = review.Spec.NonResourceAttributes.Verb
	}

	request.ResourceRequest = review.Spec.ResourceAttributes != nil

	allowed, reason, err := s.authz.Authorize(request)
	if err != nil {
		return response, err
	}
	if !allowed {
		response.Status = v1beta1.SubjectAccessReviewStatus{
			Allowed: false,
			Reason:  reason,
		}

		return response, nil
	}

	response.Status = v1beta1.SubjectAccessReviewStatus{Allowed: true}

	return response, nil
}
