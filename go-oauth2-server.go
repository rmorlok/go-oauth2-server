package main

import (
	"log"
	"os"

	"github.com/RichardKnop/go-oauth2-server/cmd"
	"github.com/RichardKnop/go-oauth2-server/config"
	"github.com/urfave/cli"
)

var (
	cliApp           *cli.App
	configBackend    string
	testMode         bool
	testDBPath       string
	testPort         int
	telemetryEnabled bool
	otelEndpoint     string
	otelProtocol     string
	otelServiceName  string
	otelInsecure     bool
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
			Name:        "telemetry, test-telemetry",
			Usage:       "enable OpenTelemetry export",
			EnvVar:      "GO_OAUTH2_TELEMETRY_ENABLED,GO_OAUTH2_TEST_TELEMETRY_ENABLED",
			Destination: &telemetryEnabled,
		},
		cli.StringFlag{
			Name:        "otel-endpoint, test-otel-endpoint",
			Usage:       "OTLP endpoint; standard OTEL_EXPORTER_OTLP_ENDPOINT also applies",
			EnvVar:      "GO_OAUTH2_OTEL_ENDPOINT,GO_OAUTH2_TEST_OTEL_ENDPOINT",
			Destination: &otelEndpoint,
		},
		cli.StringFlag{
			Name:        "otel-protocol, test-otel-protocol",
			Usage:       "OTLP protocol: grpc or http/protobuf",
			EnvVar:      "GO_OAUTH2_OTEL_PROTOCOL,GO_OAUTH2_TEST_OTEL_PROTOCOL",
			Destination: &otelProtocol,
		},
		cli.StringFlag{
			Name:        "otel-service-name, test-otel-service-name",
			Usage:       "service.name resource attribute for telemetry",
			EnvVar:      "GO_OAUTH2_OTEL_SERVICE_NAME,GO_OAUTH2_TEST_OTEL_SERVICE_NAME",
			Destination: &otelServiceName,
		},
		cli.BoolFlag{
			Name:        "otel-insecure, test-otel-insecure",
			Usage:       "use insecure OTLP transport",
			EnvVar:      "GO_OAUTH2_OTEL_INSECURE,GO_OAUTH2_TEST_OTEL_INSECURE",
			Destination: &otelInsecure,
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
					return cmd.RunTestServer(testDBPath, testPort, telemetryOptions())
				}
				return cmd.RunServer(configBackend, telemetryOptions())
			},
		},
	}

	// Run the CLI app
	if err := cliApp.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func telemetryOptions() config.TelemetryOptions {
	return config.TelemetryOptions{
		Enabled:     telemetryEnabled,
		Endpoint:    otelEndpoint,
		Protocol:    otelProtocol,
		ServiceName: otelServiceName,
		Insecure:    otelInsecure,
	}
}
