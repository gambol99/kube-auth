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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionHandler(t *testing.T) {
	s := newTestService(t)
	defer s.Close()
	res, err := hc.R().Get(s.URL() + "/version")
	assert.NotNil(t, res)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode())
}

func TestHealthHandler(t *testing.T) {
	s := newTestService(t)
	defer s.Close()
	res, err := hc.R().Get(s.URL() + "/health")
	assert.NotNil(t, res)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode())
}

func TestAuthorizeNotfound(t *testing.T) {
	s := newTestService(t)
	defer s.Close()
	res, err := hc.R().Post(s.URL() + "/authorize/not_there")
	assert.NotNil(t, res)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, res.StatusCode())
}

func TestAuthorizeDecodeBad(t *testing.T) {
	s := newTestService(t)
	defer s.Close()
	res, err := hc.R().Post(s.URL() + "/authorize/token")
	assert.NotNil(t, res)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode())
}
