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
	"fmt"
	"net/http"

	auth "k8s.io/kubernetes/pkg/apis/authentication/v1beta1"
	authz "k8s.io/kubernetes/pkg/apis/authorization/v1beta1"

	"github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
)

// authorizeHandler is responsible for verifying the tokens or a user request
func (r *service) authorizeHandler(cx *gin.Context) {
	kind := cx.Param("kind")
	// step: decode the input
	var review interface{}
	switch kind {
	case "token":
		review = new(auth.TokenReview)
	case "policy":
		review = new(authz.SubjectAccessReview)
	default:
		cx.AbortWithStatus(http.StatusNotFound)
		return
	}

	// step: decode the payload
	if err := cx.BindJSON(review); err != nil {
		logrus.WithFields(logrus.Fields{
			"client_ip": cx.ClientIP(),
			"kind":      kind,
			"error":     err.Error(),
		}).Error("unable to decode request")

		cx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{
		"client_ip": cx.ClientIP(),
		"kind":      kind,
		"incoming":  fmt.Sprintf("%#v", review),
	}).Debug("incoming request")

	// step: authenticate the token
	var result interface{}
	var err error
	switch kind {
	case "token":
		result, err = r.authentication(review.(*auth.TokenReview))
	case "policy":
		result, err = r.authorize(review.(*authz.SubjectAccessReview))
	}
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"client_ip": cx.ClientIP(),
			"kind":      kind,
			"error":     err.Error(),
		}).Error("unable to process request")

		cx.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	logrus.WithFields(logrus.Fields{
		"client_ip": cx.ClientIP(),
		"kind":      kind,
		"response":  fmt.Sprintf("%#v", result),
	}).Debug("response to request")

	// step: return the result
	cx.JSON(http.StatusOK, result)
}

//
// healthHandler is responsible for showing the health
//
func (r *service) healthHandler(cx *gin.Context) {
	cx.String(http.StatusOK, "OK\n")
}

//
// versionHandler is responsible for showing the version
//
func (r *service) versionHandler(cx *gin.Context) {
	cx.String(http.StatusOK, "%s\n", version)
}
