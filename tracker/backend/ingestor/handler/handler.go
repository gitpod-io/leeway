package handler

import (
	context "context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	connect_go "github.com/bufbuild/connect-go"
	v1 "github.com/gitpod-io/leeway/pkg/remotereporter/api/gen/v1"
	"github.com/gitpod-io/leeway/pkg/remotereporter/api/gen/v1/v1connect"
	"github.com/sirupsen/logrus"
)

func NewBuildReportHandler(store SampleStorageFunc) *BuildReportHandler {
	hdlr := &BuildReportHandler{
		storeSample: store,
	}
	return hdlr
}

type BuildReportHandler struct {
	Config      aws.Config
	storeSample SampleStorageFunc

	v1connect.UnimplementedReporterServiceHandler
}

// BuildFinished implements v1connect.ReporterServiceHandler
func (handler *BuildReportHandler) BuildFinished(ctx context.Context, req *connect_go.Request[v1.BuildFinishedRequest]) (*connect_go.Response[v1.EmptyResponse], error) {
	logrus.WithField("session", req.Msg.SessionId).WithField("pkg", req.Msg.Package.Name).Debug("BuildFinished")
	return &connect_go.Response[v1.EmptyResponse]{Msg: &v1.EmptyResponse{}}, nil
}

// BuildStarted implements v1connect.ReporterServiceHandler
func (handler *BuildReportHandler) BuildStarted(ctx context.Context, req *connect_go.Request[v1.BuildStartedRequest]) (*connect_go.Response[v1.EmptyResponse], error) {
	logrus.WithField("session", req.Msg.SessionId).WithField("pkg", req.Msg.Package.Name).WithField("status", req.Msg.Status).Debug("BuildStarted")
	return &connect_go.Response[v1.EmptyResponse]{Msg: &v1.EmptyResponse{}}, nil
}

// PackageBuildFinished implements v1connect.ReporterServiceHandler
func (handler *BuildReportHandler) PackageBuildFinished(ctx context.Context, req *connect_go.Request[v1.PackageBuildFinishedRequest]) (*connect_go.Response[v1.EmptyResponse], error) {
	var status PackageStatus
	switch {
	case req.Msg.Error != "":
		status = PackageStatusFailed
	default:
		status = PackageStatusSuccess
	}
	sample := PackageSample{
		FullName:         req.Msg.Package.Name,
		BuildDuration:    time.Duration(req.Msg.DurationMs) * time.Millisecond,
		Time:             time.Now(),
		Status:           status,
		DirtyWorkingCopy: req.Msg.Package.DirtyWorkingCopy,
		Type:             req.Msg.Package.Type,
	}
	err := handler.storeSample(ctx, sample)
	if err != nil {
		return nil, err
	}

	logrus.WithField("session", req.Msg.SessionId).WithField("pkg", req.Msg.Package.Name).WithField("dur", req.Msg.DurationMs).WithField("success", req.Msg.Error == "").Debug("PackageBuildFinished")
	return &connect_go.Response[v1.EmptyResponse]{Msg: &v1.EmptyResponse{}}, nil
}

// PackageBuildLog implements v1connect.ReporterServiceHandler
func (handler *BuildReportHandler) PackageBuildLog(ctx context.Context, req *connect_go.Request[v1.PackageBuildLogRequest]) (*connect_go.Response[v1.EmptyResponse], error) {
	logrus.WithField("session", req.Msg.SessionId).WithField("pkg", req.Msg.PackageName).Debug("PackageBuildLog")
	return &connect_go.Response[v1.EmptyResponse]{Msg: &v1.EmptyResponse{}}, nil
}

// PackageBuildStarted implements v1connect.ReporterServiceHandler
func (handler *BuildReportHandler) PackageBuildStarted(ctx context.Context, req *connect_go.Request[v1.PackageBuildStartedRequest]) (*connect_go.Response[v1.EmptyResponse], error) {
	logrus.WithField("session", req.Msg.SessionId).WithField("pkg", req.Msg.Package.Name).WithField("dirtyWorkingCopy", req.Msg.Package.DirtyWorkingCopy).Debug("PackageBuildStarted")
	return &connect_go.Response[v1.EmptyResponse]{Msg: &v1.EmptyResponse{}}, nil
}

var _ v1connect.ReporterServiceHandler = ((*BuildReportHandler)(nil))
