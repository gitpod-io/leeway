package remotereporter

import (
	"context"
	"time"

	connect_go "github.com/bufbuild/connect-go"
	"github.com/gitpod-io/leeway/pkg/leeway"
	v1 "github.com/gitpod-io/leeway/pkg/remotereporter/api/gen/v1"
	"github.com/gitpod-io/leeway/pkg/remotereporter/api/gen/v1/v1connect"
	"github.com/sirupsen/logrus"
)

type Reporter struct {
	Client v1connect.ReporterServiceClient

	sessionID string
}

var _ leeway.Reporter = ((*Reporter)(nil))

// BuildFinished implements leeway.Reporter
func (rep *Reporter) BuildFinished(pkg *leeway.Package, err error) {
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	logError(rep.Client.BuildFinished(rep.context(), &connect_go.Request[v1.BuildFinishedRequest]{
		Msg: &v1.BuildFinishedRequest{
			SessionId: rep.session(),
			Package:   toRemotePackage(pkg),
			Error:     errMsg,
		},
	}))
}

// BuildStarted implements leeway.Reporter
func (rep *Reporter) BuildStarted(pkg *leeway.Package, status map[*leeway.Package]leeway.PackageBuildStatus) {
	msgStatus := make(map[string]v1.PackageBuildStatus, len(status))
	for k, v := range status {
		s := v1.PackageBuildStatus_PACKAGE_BUILD_STATUS_UNSPECIFIED
		switch v {
		case leeway.PackageBuilding:
			s = v1.PackageBuildStatus_PACKAGE_BUILD_STATUS_BUILDING
		case leeway.PackageBuilt:
			s = v1.PackageBuildStatus_PACKAGE_BUILD_STATUS_BUILT
		case leeway.PackageDownloaded:
			s = v1.PackageBuildStatus_PACKAGE_BUILD_STATUS_DOWNLOADED
		case leeway.PackageInRemoteCache:
			s = v1.PackageBuildStatus_PACKAGE_BUILD_STATUS_IN_REMOTE_CACHE
		case leeway.PackageNotBuiltYet:
			s = v1.PackageBuildStatus_PACKAGE_BUILD_STATUS_NOT_BUILT_YET
		}
		msgStatus[k.Name] = s
	}
	logError(rep.Client.BuildStarted(rep.context(), &connect_go.Request[v1.BuildStartedRequest]{
		Msg: &v1.BuildStartedRequest{
			SessionId: rep.session(),
			Package:   toRemotePackage(pkg),
			Status:    msgStatus,
		},
	}))
}

// PackageBuildFinished implements leeway.Reporter
func (rep *Reporter) PackageBuildFinished(pkg *leeway.Package, err error) {
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	logError(rep.Client.PackageBuildFinished(rep.context(), &connect_go.Request[v1.PackageBuildFinishedRequest]{
		Msg: &v1.PackageBuildFinishedRequest{
			SessionId:   rep.session(),
			PackageName: pkg.Name,
			Error:       errMsg,
		},
	}))
}

// PackageBuildLog implements leeway.Reporter
func (rep *Reporter) PackageBuildLog(pkg *leeway.Package, isErr bool, buf []byte) {
	logError(rep.Client.PackageBuildLog(rep.context(), &connect_go.Request[v1.PackageBuildLogRequest]{
		Msg: &v1.PackageBuildLogRequest{
			SessionId:   rep.session(),
			PackageName: pkg.Name,
			Message:     buf,
			IsError:     isErr,
		},
	}))
}

// PackageBuildStarted implements leeway.Reporter
func (rep *Reporter) PackageBuildStarted(pkg *leeway.Package) {
	logError(rep.Client.PackageBuildStarted(rep.context(), &connect_go.Request[v1.PackageBuildStartedRequest]{
		Msg: &v1.PackageBuildStartedRequest{
			SessionId: rep.session(),
			Package:   toRemotePackage(pkg),
		},
	}))
}

func (rep *Reporter) session() string {
	if rep.sessionID == "" {
		rep.sessionID = time.Now().Format(time.RFC3339Nano)
	}
	return rep.sessionID
}

func (rep *Reporter) context() context.Context { return context.TODO() }

func toRemotePackage(pkg *leeway.Package) *v1.Package {
	pkgType := v1.PackageType_PACKAGE_TYPE_UNSPECIFIED
	switch pkg.Type {
	case leeway.DockerPackage:
		pkgType = v1.PackageType_PACKAGE_TYPE_DOCKER
	case leeway.GenericPackage:
		pkgType = v1.PackageType_PACKAGE_TYPE_GENERIC
	case leeway.GoPackage:
		pkgType = v1.PackageType_PACKAGE_TYPE_GO
	case leeway.YarnPackage:
		pkgType = v1.PackageType_PACKAGE_TYPE_YARN
	}

	return &v1.Package{
		Name:         pkg.Name,
		Type:         pkgType,
		Sources:      pkg.Sources,
		Dependencies: pkg.Dependencies,
	}
}

func logError(_ *connect_go.Response[v1.EmptyResponse], err error) {
	if err == nil {
		return
	}

	logrus.WithError(err).Error("cannot report build progress")
}
