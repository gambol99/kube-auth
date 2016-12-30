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
	"io/ioutil"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-resty/resty"
	"github.com/stretchr/testify/assert"
)

const (
	defaultTestTokens = `
token1,user1,uuid1
token2,user2,uuid2
token3,user3,uuid3,group3
`
	defaultTestAuthPolicy = `
{"apiVersion":"abac.authorization.kubernetes.io/v1beta1","kind":"Policy","spec":{ "user":"admin", "namespace": "*", "resource": "*" }}
{"apiVersion":"abac.authorization.kubernetes.io/v1beta1","kind":"Policy","spec":{ "user":"user1", "namespace": "adm", "resource": "*" }}
{"apiVersion":"abac.authorization.kubernetes.io/v1beta1","kind":"Policy","spec":{ "user":"user1", "namespace": "adm-dev", "resource": "*" }}
{"apiVersion":"abac.authorization.kubernetes.io/v1beta1","kind":"Policy","spec":{ "user":"user2", "namespace": "adm-preprod", "resource": "*" }}
{"apiVersion":"abac.authorization.kubernetes.io/v1beta1","kind":"Policy","spec":{ "user":"user3", "namespace": "te", "resource": "*" }}
{"apiVersion":"abac.authorization.kubernetes.io/v1beta1","kind":"Policy","spec":{ "user":"user3", "namespace": "te-dev", "resource": "*" }}
{"apiVersion":"abac.authorization.kubernetes.io/v1beta1","kind":"Policy","spec":{ "user":"user3", "namespace": "te-preprod", "resource": "*" }}
{"apiVersion":"abac.authorization.kubernetes.io/v1beta1","kind":"Policy","spec":{ "user":"user2", "namespace": "sip-demo", "resource": "*" }}
{"apiVersion":"abac.authorization.kubernetes.io/v1beta1","kind":"Policy","spec":{ "group":"group3", "namespace": "sip-demo", "resource": "*" }}
{"apiVersion":"abac.authorization.kubernetes.io/v1beta1","kind":"Policy","spec":{ "user":"*", "nonResourcePath": "*", "readonly": true }}
`
)

var (
	hc = resty.New()
)

type testService struct {
	s   *service
	svc *httptest.Server
}

func (t *testService) URL() string {
	return t.svc.URL
}

func (t *testService) Close() {
	if t.s.cfg.tokenFile != "" {
		os.Remove(t.s.cfg.tokenFile)
	}
	if t.s.cfg.authFile != "" {
		os.Remove(t.s.cfg.authFile)
	}
}

func newTestService(t *testing.T) *testService {
	s, err := newTestingService(defaultTestTokens, defaultTestAuthPolicy)
	if err != nil {
		t.Fatalf("unable to create service, error: %s", err)
	}

	return s
}

func newTestingService(tokens, auth string) (*testService, error) {
	opts := options{
		listen:  "127.0.0.1:8080",
		tlsCert: "does_not_exist",
		tlsKey:  "does_not_exist",
	}

	// step: write the test tokens file
	t, err := writeTestFile(tokens)
	if err != nil {
		return nil, err
	}
	opts.tokenFile = t.Name()

	// step: create the auth policy
	t, err = writeTestFile(auth)
	if err != nil {
		return nil, err
	}
	opts.authFile = t.Name()

	s, err := newService(opts)
	if err != nil {
		return nil, err
	}

	svc := httptest.NewServer(s.engine)

	return &testService{
		s:   s,
		svc: svc,
	}, nil
}

func TestLoadTokensFile(t *testing.T) {
	f, err := writeTestFile(defaultTestTokens)
	if err != nil {
		t.Fatalf("failed to write the tokens file, error: %s", err)
	}
	defer os.Remove(f.Name())

	x, err := loadTokensFile(f.Name())
	assert.NotNil(t, x)
	assert.NoError(t, err)

	x, err = loadTokensFile("should_not_exist_file")
	assert.Nil(t, x)
	assert.Error(t, err)
}

func TestLoadAuthorizationFile(t *testing.T) {
	f, err := writeTestFile(defaultTestAuthPolicy)
	if err != nil {
		t.Fatalf("failed to write the auth file, error: %s", err)
	}
	defer os.Remove(f.Name())

	x, err := loadAuthorizationFile(f.Name())
	assert.NotNil(t, x)
	assert.NoError(t, err)

	x, err = loadAuthorizationFile("should_not_exist_file")
	assert.Nil(t, x)
	assert.Error(t, err)
}

func TestComputeSum(t *testing.T) {
	f, err := writeTestFile(defaultTestTokens)
	if err != nil {
		t.Fatalf("failed to write the tokens file, error: %s", err)
	}
	defer os.Remove(f.Name())

	sum, err := computeSum(f.Name())
	assert.NoError(t, err)
	assert.Equal(t, [16]byte{0xbe, 0x8f, 0x41, 0xa3, 0x6f, 0x87, 0x6c, 0x6b, 0x7c, 0x3, 0x20, 0xe1, 0x6f, 0x2, 0xcf, 0x5c}, sum)

	_, err = computeSum("file_does_not_exist")
	assert.Error(t, err)
}

func writeTestFile(content string) (*os.File, error) {
	f, err := ioutil.TempFile("/tmp", "kube-auth.XXXXXXXX")
	if err != nil {
		return nil, err
	}

	f.WriteString(content)

	return f, nil
}

func updateTestFile(t *testing.T, filename, content string) {
	fd, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0664)
	if err != nil {
		t.Errorf("failed to update the file %s, error: %s", filename, err)
		t.FailNow()
	}

	fd.WriteString(content)
	fd.Close()

	return
}
