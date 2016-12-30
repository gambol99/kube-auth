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
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli"
)

func main() {
	var opts options

	app := cli.NewApp()
	app.Usage = "provides a kubernetes webhook service to tokens and abac policy"
	app.Author = "Rohith Jayawardene"
	app.Email = "gambol99@gmail.com"
	app.Version = version

	app.OnUsageError = func(context *cli.Context, err error, isSubcommand bool) error {
		fmt.Fprintf(os.Stderr, "[error] invalid options, %s\n", err)
		return err
	}

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "listen",
			Usage:       "the interface and port the service should bind",
			Value:       "127.0.0.1:8443",
			Destination: &opts.listen,
		},
		cli.StringFlag{
			Name:        "token-file",
			Usage:       "the path to the file containing the tokens",
			Destination: &opts.tokenFile,
		},
		cli.StringFlag{
			Name:        "auth-policy",
			Usage:       "the path to the file containing the auth policy",
			Destination: &opts.authFile,
		},
		cli.StringFlag{
			Name:        "tls-cert",
			Usage:       "the path to a file containing the certificate to use",
			Destination: &opts.tlsCert,
		},
		cli.StringFlag{
			Name:        "tls-key",
			Usage:       "the path to a file containing the private key",
			Destination: &opts.tlsKey,
		},
		cli.StringFlag{
			Name:        "tls-ca",
			Usage:       "the path to a file containing a CA certificate for client auth",
			Destination: &opts.tlsCA,
		},
		cli.BoolTFlag{
			Name:        "disable-logging",
			Usage:       "disable all logging messages",
			Destination: &opts.logging,
		},
		cli.BoolFlag{
			Name:        "verbose",
			Usage:       "switch on verbose logging",
			Destination: &opts.verbose,
		},
	}
	// step: the default action to run
	app.Action = func(cx *cli.Context) error {
		// step: create the service
		s, err := newService(opts)
		if err != nil {
			errorMessage(fmt.Sprintf("unable to create service, error: %s", err))
		}

		// step: run the service
		if err := s.run(); err != nil {
			errorMessage(fmt.Sprintf("unable to run service, error: %s", err))
		}

		// step: wait for the termination signal
		signalChannel := make(chan os.Signal)
		signal.Notify(signalChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		<-signalChannel

		return nil
	}

	app.Run(os.Args)
}

func errorMessage(message string) {
	fmt.Fprintf(os.Stderr, "[error] "+message)
	os.Exit(1)
}
