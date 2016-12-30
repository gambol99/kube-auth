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

	"k8s.io/kubernetes/pkg/apis/authentication/v1beta1"

	"github.com/stretchr/testify/assert"
	"k8s.io/kubernetes/pkg/api/unversioned"
)

var failedAuthRequest = v1beta1.TokenReview{
	TypeMeta: unversioned.TypeMeta{
		APIVersion: "authentication.k8s.io/v1beta1",
		Kind:       "TokenReview",
	},
	Status: v1beta1.TokenReviewStatus{
		Authenticated: false,
		Error:         "token not found",
	},
}

func TestAuthenticate(t *testing.T) {
	s := newTestService(t)
	defer s.Close()

	cs := []struct {
		token  string
		ok     bool
		expect v1beta1.TokenReview
	}{
		{
			token:  "bad_token",
			expect: failedAuthRequest,
		},
		{
			token: "token1",
			ok:    true,
			expect: v1beta1.TokenReview{
				TypeMeta: unversioned.TypeMeta{
					APIVersion: "authentication.k8s.io/v1beta1",
					Kind:       "TokenReview",
				},
				Status: v1beta1.TokenReviewStatus{
					Authenticated: true,
					User: v1beta1.UserInfo{
						Username: "user1",
						UID:      "uuid1",
					},
				},
			},
		},
		{
			token: "token3",
			ok:    true,
			expect: v1beta1.TokenReview{
				TypeMeta: unversioned.TypeMeta{
					APIVersion: "authentication.k8s.io/v1beta1",
					Kind:       "TokenReview",
				},
				Status: v1beta1.TokenReviewStatus{
					Authenticated: true,
					User: v1beta1.UserInfo{
						Username: "user3",
						UID:      "uuid3",
						Groups:   []string{"group3"},
					},
				},
			},
		},
	}
	for _, x := range cs {
		status, err := makeTestAuthRequest(s.URL(),
			v1beta1.TokenReview{
				Spec: v1beta1.TokenReviewSpec{
					Token: x.token,
				},
			})
		if !assert.NoError(t, err) {
			continue
		}
		assert.Equal(t, x.expect, status)
	}
}

func TestAuthenticationFileChange(t *testing.T) {
	s := newTestService(t)
	defer s.Close()

	expected := v1beta1.TokenReview{
		TypeMeta: unversioned.TypeMeta{
			APIVersion: "authentication.k8s.io/v1beta1",
			Kind:       "TokenReview",
		},
		Status: v1beta1.TokenReviewStatus{
			Authenticated: true,
			User: v1beta1.UserInfo{
				UID:      "uuid5",
				Username: "user5",
				Groups:   []string{"group1", "group2"},
			},
		},
	}

	request := v1beta1.TokenReview{
		Spec: v1beta1.TokenReviewSpec{
			Token: "token5",
		},
	}

	status, err := makeTestAuthRequest(s.URL(), request)
	if !assert.NoError(t, err) {
		t.Failed()
	}
	assert.Equal(t, failedAuthRequest, status)

	// step: now lets update the file and get it reloaded
	updateTestFile(t, s.s.cfg.tokenFile, "token5,user5,uuid5,\"group1,group2\"\n")

	time.Sleep(800 * time.Millisecond)

	status, err = makeTestAuthRequest(s.URL(), request)
	if !assert.NoError(t, err) {
		t.Failed()
	}
	assert.Equal(t, expected, status)
}

func makeTestAuthRequest(url string, review v1beta1.TokenReview) (v1beta1.TokenReview, error) {
	var result v1beta1.TokenReview
	res, err := hc.R().
		SetHeader("Content-Type", "application/json").
		SetBody(review).
		SetResult(&result).
		Post(url + "/authorize/token")
	if err != nil {
		return result, err
	}
	if res.StatusCode() != http.StatusOK {
		return result, errors.New("invalid response from api")
	}

	return result, nil
}
