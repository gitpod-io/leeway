package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	grpcreflect "github.com/bufbuild/connect-grpcreflect-go"
	"github.com/sirupsen/logrus"

	"github.com/gitpod-io/leeway/pkg/remotereporter/api/gen/v1/v1connect"
	"github.com/gitpod-io/leeway/tracker/backend/ingestor/handler"
)

var (
	listen = flag.String("listen", ":8080", "address to listen on when not running as lambda")
)

func main() {
	flag.Parse()

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	mux.Handle(v1connect.NewReporterServiceHandler(handler.NewBuildReportHandler(cfg)))

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
