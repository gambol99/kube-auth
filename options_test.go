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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsIsValid(t *testing.T) {
	cs := []struct {
		Opts options
		Err  error
	}{
		{
			Err: errors.New("no listen"),
		},
		{
			Opts: options{
				listen: "127.0.0.1:8080",
			},
			Err: errors.New("no tls cert"),
		},
		{
			Opts: options{
				listen:  "127.0.0.1:8080",
				tlsCert: "no_cert",
			},
			Err: errors.New("no tls key"),
		},
		{
			Opts: options{
				listen:  "127.0.0.1:8080",
				tlsCert: "no_cert",
				tlsKey:  "no_key",
			},
			Err: errors.New("no tokens file"),
		},
		{
			Opts: options{
				listen:    "127.0.0.1:8080",
				tlsCert:   "no_cert",
				tlsKey:    "no_key",
				tokenFile: "token_file",
			},
			Err: nil,
		},
	}
	for _, x := range cs {
		err := x.Opts.isValid()
		assert.Equal(t, x.Err, err)
	}
}
