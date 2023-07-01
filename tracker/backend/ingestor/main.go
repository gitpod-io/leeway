package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/InfluxCommunity/influxdb3-go/influx"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	grpcreflect "github.com/bufbuild/connect-grpcreflect-go"
	"github.com/sirupsen/logrus"

	"github.com/gitpod-io/leeway/pkg/remotereporter/api/gen/v1/v1connect"
	"github.com/gitpod-io/leeway/tracker/backend/ingestor/handler"
)

var (
	listen     = flag.String("listen", ":8080", "address to listen on when not running as lambda")
	verbose    = flag.Bool("verbose", false, "enable verbose logging")
	sampleSink = flag.String("sample-sink", "console", "where to write samples to. Valid values are: console, cloudwatch")
)

func main() {
	flag.Parse()

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	var store handler.SampleStorageFunc
	switch *sampleSink {
	case "console":
		store = handler.PrintSample
	case "cloudwatch":
		store = handler.PutCloudwatchMetric(cloudwatch.NewFromConfig(cfg))
	case "influxdb":
		client, err := influx.New(influx.Configs{
			HostURL:      os.Getenv("INFLUXDB_HOST"),
			AuthToken:    os.Getenv("INFLUXDB_TOKEN"),
			Organization: os.Getenv("INFLUXDB_ORG"),
			HTTPClient:   &http.Client{Timeout: 5 * time.Second},
		})
		if err != nil {
			log.Fatalf("cannot create InfluxDB client: %v", err)
		}
		store = handler.WriteToInfluxDB(client, os.Getenv("INFLUXDB_DATABASE"))
	default:
		logrus.Fatalf("unsupported --sample-sink: %s", *sampleSink)
	}
	mux.Handle(v1connect.NewReporterServiceHandler(handler.NewBuildReportHandler(store)))

	reflector := grpcreflect.NewStaticReflector(
		v1connect.ReporterServiceName,
	)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))
	mux.Handle("/health", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	if os.Getenv("AWS_LAMBDA_RUNTIME_API") == "" {
		flag.Parse()
		logrus.WithField("addr", *listen).Info("starting server directly")
		err = http.ListenAndServe(*listen, mux)
		if err != nil {
			logrus.WithError(err).Fatal("cannot start server directly")
		}
	}

	lambda.Start(httpadapter.NewV2(mux).ProxyWithContext)
}
