package main

import (
	"log"
	"os"

	"github.com/RichardKnop/go-oauth2-server/cmd"
	"github.com/RichardKnop/go-oauth2-server/testmode"
	"github.com/urfave/cli"
)

var (
	cliApp              *cli.App
	configBackend       string
	testMode            bool
	testDBPath          string
	testPort            int
	testTelemetry       bool
	testOTELEndpoint    string
	testOTELProtocol    string
	testOTELServiceName string
	testOTELInsecure    bool
)

func init() {
	// Initialise a CLI app
	cliApp = cli.NewApp()
	cliApp.Name = "go-oauth2-server"
	cliApp.Usage = "Go OAuth 2.0 Server"
	cliApp.Author = "Richard Knop"
	cliApp.Email = "risoknop@gmail.com"
	cliApp.Version = "0.0.0"
	cliApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "configBackend",
			Value:       "etcd",
			Destination: &configBackend,
		},
	}
}

func main() {
	runserverFlags := []cli.Flag{
		cli.BoolFlag{
			Name:        "test-mode",
			Usage:       "run as a controllable test provider: use embedded SQLite, skip remote config, expose /test/* control plane",
			Destination: &testMode,
		},
		cli.StringFlag{
			Name:        "test-db-path",
			Usage:       "path to SQLite database file (default: in-memory). Only used with --test-mode",
			Value:       ":memory:",
			Destination: &testDBPath,
		},
		cli.IntFlag{
			Name:        "test-port",
			Usage:       "port to bind in test mode",
			Value:       8080,
			Destination: &testPort,
		},
		cli.BoolFlag{
			Name:        "test-telemetry",
			Usage:       "enable OpenTelemetry export in test mode",
			EnvVar:      "GO_OAUTH2_TEST_TELEMETRY_ENABLED",
			Destination: &testTelemetry,
		},
		cli.StringFlag{
			Name:        "test-otel-endpoint",
			Usage:       "OTLP endpoint for test-mode telemetry; standard OTEL_EXPORTER_OTLP_ENDPOINT also applies",
			EnvVar:      "GO_OAUTH2_TEST_OTEL_ENDPOINT",
			Destination: &testOTELEndpoint,
		},
		cli.StringFlag{
			Name:        "test-otel-protocol",
			Usage:       "OTLP protocol for test-mode telemetry: grpc or http/protobuf",
			EnvVar:      "GO_OAUTH2_TEST_OTEL_PROTOCOL",
			Destination: &testOTELProtocol,
		},
		cli.StringFlag{
			Name:        "test-otel-service-name",
			Usage:       "service.name resource attribute for test-mode telemetry",
			EnvVar:      "GO_OAUTH2_TEST_OTEL_SERVICE_NAME",
			Destination: &testOTELServiceName,
		},
		cli.BoolFlag{
			Name:        "test-otel-insecure",
			Usage:       "use insecure OTLP transport in test mode",
			EnvVar:      "GO_OAUTH2_TEST_OTEL_INSECURE",
			Destination: &testOTELInsecure,
		},
	}

	// Set the CLI app commands
	cliApp.Commands = []cli.Command{
		{
			Name:  "migrate",
			Usage: "run migrations",
			Action: func(c *cli.Context) error {
				return cmd.Migrate(configBackend)
			},
		},
		{
			Name:  "loaddata",
			Usage: "load data from fixture",
			Action: func(c *cli.Context) error {
				return cmd.LoadData(c.Args(), configBackend)
			},
		},
		{
			Name:  "runserver",
			Usage: "run web server",
			Flags: runserverFlags,
			Action: func(c *cli.Context) error {
				if testMode {
					return cmd.RunTestServer(testDBPath, testPort, testmodeConfigOptions())
				}
				return cmd.RunServer(configBackend)
			},
		},
	}

	// Run the CLI app
	if err := cliApp.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func testmodeConfigOptions() testmode.ConfigOptions {
	return testmode.ConfigOptions{
		TelemetryEnabled:     testTelemetry,
		TelemetryEndpoint:    testOTELEndpoint,
		TelemetryProtocol:    testOTELProtocol,
		TelemetryServiceName: testOTELServiceName,
		TelemetryInsecure:    testOTELInsecure,
	}
}
