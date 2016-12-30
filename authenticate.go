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
	"k8s.io/kubernetes/pkg/apis/authentication/v1beta1"
)

// authentication is responsible for authenticating the user
func (s *service) authentication(review *v1beta1.TokenReview) (v1beta1.TokenReview, error) {
	s.RLock()
	defer s.RUnlock()

	var response = v1beta1.TokenReview{
		TypeMeta: unversioned.TypeMeta{
			APIVersion: "authentication.k8s.io/v1beta1",
			Kind:       "TokenReview",
		},
	}

	user, found, err := s.tokens.AuthenticateToken(review.Spec.Token)
	if err != nil {
		return response, err
	}
	if !found {
		response.Status = v1beta1.TokenReviewStatus{Authenticated: false, Error: "token not found"}
		return response, nil
	}

	response.Status = v1beta1.TokenReviewStatus{
		Authenticated: true,
		User: v1beta1.UserInfo{
			UID:      user.GetUID(),
			Username: user.GetName(),
			Groups:   user.GetGroups(),
		},
	}

	return response, nil
}
