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
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
)

// loggingMiddleware is a custom http logger
func (r *service) loggingMiddleware() gin.HandlerFunc {
	return func(cx *gin.Context) {
		start := time.Now()
		cx.Next()
		latency := time.Now().Sub(start)

		logrus.WithFields(logrus.Fields{
			"client_ip": cx.ClientIP(),
			"method":    cx.Request.Method,
			"status":    cx.Writer.Status(),
			"bytes":     cx.Writer.Size(),
			"path":      cx.Request.URL.Path,
			"latency":   latency.String(),
		}).Infof("[%d] |%s| |%10v| %-5s %s", cx.Writer.Status(), cx.ClientIP(), latency, cx.Request.Method, cx.Request.URL.Path)
	}
}
