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
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"path"
	"sync"

	"k8s.io/kubernetes/pkg/auth/authorizer/abac"
	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/tokenfile"

	"github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
	"gopkg.in/fsnotify.v1"
)

// is the service wrapper
type service struct {
	sync.RWMutex
	cfg    *options
	engine *gin.Engine
	tokens authentication
	authz  authorization
	files  map[string][16]byte
}

// newService is responsible for creating the service
func newService(o options) (*service, error) {
	// step: disable logging
	logrus.SetFormatter(&logrus.JSONFormatter{})
	if !o.logging {
		logrus.SetOutput(ioutil.Discard)
	}
	if o.verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	// step: check the options are valid
	if err := o.isValid(); err != nil {
		return nil, err
	}

	s := &service{
		cfg:   &o,
		files: make(map[string][16]byte, 0),
	}

	// step: create the endpoints
	if err := s.createEndpoints(); err != nil {
		return nil, err
	}

	// step: create the watcher
	if err := s.createWatcher(); err != nil {
		return nil, err
	}

	// step: load the tokens file
	t, err := loadTokensFile(s.cfg.tokenFile)
	if err != nil {
		return nil, err
	}
	s.tokens = t

	// step: load the abac file if required
	if s.cfg.authFile != "" {
		t, err := loadAuthorizationFile(s.cfg.authFile)
		if err != nil {
			return nil, err
		}
		s.authz = t
	}

	return s, nil
}

// createWatcher is responsible for watching for changes in the token and auth files
func (s *service) createWatcher() error {
	// step: create the watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	// step: add the directories to be watched
	watching := make(map[string]bool, 0)
	for _, x := range []string{s.cfg.tokenFile, s.cfg.authFile} {
		if x == "" {
			continue
		}
		s.files[x] = [16]byte{}

		dir := path.Dir(x)
		if _, found := watching[x]; found {
			continue
		}
		watching[dir] = true

		if err := watcher.Add(dir); err != nil {
			return err
		}
	}

	// step: create the event watcher
	go func() {
		for e := range watcher.Events {
			logrus.WithFields(logrus.Fields{
				"filename": e.Name,
				"event":    e.String(),
			}).Debug("recieved a file notification event")

			if e.Op&fsnotify.Write == fsnotify.Write || e.Op&fsnotify.Create == fsnotify.Create {
				if err := s.processFileEvent(e.Name); err != nil {
					logrus.WithFields(logrus.Fields{
						"filename": e.Name,
						"error":    err.Error(),
					}).Errorf("unable to process file change")
				}
			}
		}
		// @note: we should NEVER get here
		panic("we have exited the watcher rountine")
	}()

	return nil
}

// processFileEvent is responsible for handling the file changes
func (s *service) processFileEvent(filename string) error {
	// step: we only care about events related to tokens and auth file
	sum, found := s.files[filename]
	if !found {
		return nil
	}
	// step: compute the file hash
	nsum, err := computeSum(filename)
	if err != nil {
		return err
	}
	// step: if they are the same, return
	if sum == nsum {
		return nil
	}
	// step: reload the file
	switch filename {
	case s.cfg.tokenFile:
		t, err := loadTokensFile(filename)
		if err != nil {
			return err
		}
		s.Lock()
		s.files[filename] = nsum
		s.tokens = t
		s.Unlock()
	case s.cfg.authFile:
		t, err := loadAuthorizationFile(filename)
		if err != nil {
			return err
		}
		s.Lock()
		s.files[filename] = nsum
		s.authz = t
		s.Unlock()
	}

	logrus.WithFields(logrus.Fields{
		"filename": filename,
	}).Infof("reloaded the contents of the file")

	return nil
}

// run is responsible for starting the service
func (s *service) run() error {
	tlsConfig := &tls.Config{}

	// step: are run using client auth?
	if s.cfg.tlsCA != "" {
		caCert, err := ioutil.ReadFile(s.cfg.tlsCA)
		if err != nil {
			return err
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	server := &http.Server{
		Addr:    s.cfg.listen,
		Handler: s.engine,
	}

	// step: create the listener
	listener, err := net.Listen("tcp", s.cfg.listen)
	if err != nil {
		return err
	}

	// step: configure tls
	if s.cfg.tlsCert != "" && s.cfg.tlsKey != "" {
		server.TLSConfig = tlsConfig

		// step: load the certificate
		certs, err := tls.LoadX509KeyPair(s.cfg.tlsCert, s.cfg.tlsKey)
		if err != nil {
			return err
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, certs)

		listener = tls.NewListener(listener, tlsConfig)
	}

	go func() {
		if err = server.Serve(listener); err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Fatalf("failed to start the service")
		}
	}()

	return nil
}

func (s *service) createEndpoints() error {
	gin.SetMode(gin.ReleaseMode)
	if s.cfg.verbose {
		gin.SetMode(gin.DebugMode)
	}

	s.engine = gin.New()
	s.engine.Use(gin.Recovery(), s.loggingMiddleware())
	s.engine.POST("/authorize/:kind", s.authorizeHandler)
	s.engine.GET("/version", s.versionHandler)
	s.engine.GET("/health", s.healthHandler)

	return nil
}

// loadTokensFile is responsible for loading the tokens file
func loadTokensFile(filename string) (authentication, error) {
	// step: attempt to load the file
	t, err := tokenfile.NewCSV(filename)
	if err != nil {
		return nil, err
	}

	return t, nil
}

// loadAuthorizationFile is responsible for loading the authorization file
func loadAuthorizationFile(filename string) (authorization, error) {
	// step: attempt to load the file
	t, err := abac.NewFromFile(filename)
	if err != nil {
		return nil, err
	}

	return t, nil
}

// computeSum gets the md5 sum of a file
func computeSum(path string) ([16]byte, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return [16]byte{}, err
	}

	return md5.Sum(content), nil
}
