package remotereporter

import (
	context "context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/typefox/leeway/pkg/leeway"
	"google.golang.org/grpc"
)

// Reporter reports build progress using the remotereporter gRPC protocol
type Reporter struct {
	client  ReporterClient
	events  chan event
	done    chan struct{}
	session string
}

type event struct {
	Type eventType
	Msg  interface{}
}

type eventType int

const (
	eventBuildStarted eventType = iota
	eventBuildFinished
	eventPackageBuildStarted
	eventPackageBuildLog
	eventPackageBuildFinished
)

// NewRemoteReporter creates a new remote reporter reporting to the given host
func NewRemoteReporter(host string, opts ...grpc.DialOption) (*Reporter, error) {
	conn, err := grpc.Dial(host, opts...)
	if err != nil {
		return nil, err
	}

	client := NewReporterClient(conn)
	rep := &Reporter{
		client: client,
		events: make(chan event, 100),
		done:   make(chan struct{}),
	}
	go rep.send()

	return rep, nil
}

// send listens on the event channel and sends out events as they come. Exits when the connection is shut down.
func (r *Reporter) send() {
	logstream, err := r.client.PackageBuildLog(context.Background())
	if err != nil {
		log.WithError(err).Error("cannot establish log stream")
	}

recv:
	for evt := range r.events {
		var err error
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		switch evt.Type {
		case eventBuildStarted:
			resp, err := r.client.BuildStarted(ctx, evt.Msg.(*BuildStartedEvent))
			if err == nil {
				r.session = resp.Session
			}
		case eventBuildFinished:
			msg := evt.Msg.(*BuildFinishedEvent)
			msg.Session = r.session
			_, err = r.client.BuildFinished(ctx, msg)
			cancel()

			break recv
		case eventPackageBuildStarted:
			msg := evt.Msg.(*PackageBuildStartedEvent)
			msg.Session = r.session
			_, err = r.client.PackageBuildStarted(ctx, msg)
		case eventPackageBuildLog:
			if logstream != nil {
				msg := evt.Msg.(*PackageBuildLogEvent)
				msg.Session = r.session
				logstream.Send(msg)
			}
		case eventPackageBuildFinished:
			msg := evt.Msg.(*PackageBuildFinishedEvent)
			msg.Session = r.session
			_, err = r.client.PackageBuildFinished(ctx, msg)
		}

		cancel()
		if err != nil {
			log.WithError(err).Warn("error while reporting")
		}
	}

	(&sync.Once{}).Do(func() {
		close(r.done)
	})
}

func toRPCPackage(pkg *leeway.Package, status map[*leeway.Package]leeway.PackageBuildStatus) (*Package, error) {
	deps := make([]*Package, len(pkg.GetDependencies()))
	for i, dep := range pkg.GetDependencies() {
		dp, err := toRPCPackage(dep, status)
		if err != nil {
			return nil, err
		}

		deps[i] = dp
	}

	meta, err := toRPCPackageMetadata(pkg)
	if err != nil {
		return nil, err
	}
	if stat, ok := status[pkg]; ok {
		translation := map[leeway.PackageBuildStatus]PackageStatus{
			leeway.PackageNotBuiltYet: PackageStatus_NotBuilt,
			leeway.PackageBuilding:    PackageStatus_Building,
			leeway.PackageBuilt:       PackageStatus_Built,
		}
		meta.Status = translation[stat]
	}
	return &Package{
		Metadata:     meta,
		Dependencies: deps,
	}, nil
}

func toRPCPackageMetadata(pkg *leeway.Package) (*PackageMetadata, error) {
	version, err := pkg.Version()
	if err != nil {
		return nil, err
	}

	return &PackageMetadata{
		Fullname: pkg.FullName(),
		Version:  version,
		Status:   PackageStatus_Unknown,
	}, nil
}

// BuildStarted is called when the build of a package is started by the user.
// This is not the same as a dependency beeing built (see PackageBuildStarted for that).
// The root package will also be passed into PackageBuildStarted once all its depepdencies
// have been built.
func (r *Reporter) BuildStarted(pkg *leeway.Package, status map[*leeway.Package]leeway.PackageBuildStatus) {
	msgpkg, err := toRPCPackage(pkg, status)
	if err != nil {
		log.WithError(err).Error("remote reporter dropping message: BuildStarted")
	}

	msg := &BuildStartedEvent{Package: msgpkg}
	select {
	case r.events <- event{eventBuildStarted, msg}:
	default:
		log.Warn("remote reporter dropping message: BuildStarted")
	}
}

// BuildFinished is called when the build of a package whcih was started by the user has finished.
// This is not the same as a dependency build finished (see PackageBuildFinished for that).
// The root package will also be passed into PackageBuildFinished once it's been built.
func (r *Reporter) BuildFinished(pkg *leeway.Package, err error) {
	msgpkg, err := toRPCPackageMetadata(pkg)
	if err != nil {
		log.WithError(err).Error("remote reporter dropping message: BuildFinished")
	}

	var (
		message string
		failed  bool
	)
	if err != nil {
		message = err.Error()
		failed = true
	}

	msg := &BuildFinishedEvent{
		Package:    msgpkg,
		Successful: !failed,
		Message:    message,
	}
	select {
	case r.events <- event{eventBuildFinished, msg}:
	default:
		log.Warn("remote reporter dropping message: BuildFinished")
	}

	<-r.done
}

// PackageBuildStarted is called when a package build actually gets underway. At this point
// all transitive dependencies of the package have been built.
func (r *Reporter) PackageBuildStarted(pkg *leeway.Package) {
	msgpkg, err := toRPCPackageMetadata(pkg)
	if err != nil {
		log.WithError(err).Error("remote reporter dropping message: PackageBuildStarted")
	}

	msg := &PackageBuildStartedEvent{
		Package: msgpkg,
	}
	select {
	case r.events <- event{eventPackageBuildStarted, msg}:
	default:
		log.Warn("remote reporter dropping message: PackageBuildStarted")
	}
}

// PackageBuildLog is called during a package build whenever a build command produced some output.
func (r *Reporter) PackageBuildLog(pkg *leeway.Package, isErr bool, buf []byte) {
	msgpkg, err := toRPCPackageMetadata(pkg)
	if err != nil {
		log.WithError(err).Error("remote reporter dropping message: PackageBuildLog")
	}

	msg := &PackageBuildLogEvent{
		Package: msgpkg,
		Data:    buf,
	}
	select {
	case r.events <- event{eventPackageBuildLog, msg}:
	default:
		log.Warn("remote reporter dropping message: PackageBuildLog")
	}
}

// PackageBuildFinished is called when the package build has finished. If an error is passed in
// the package build was not succesfull.
func (r *Reporter) PackageBuildFinished(pkg *leeway.Package, err error) {
	msgpkg, err := toRPCPackageMetadata(pkg)
	if err != nil {
		log.WithError(err).Error("remote reporter dropping message: PackageBuildFinished")
	}

	var (
		message string
		failed  bool
	)
	if err != nil {
		message = err.Error()
		failed = true
	}

	msg := &PackageBuildFinishedEvent{
		Package:    msgpkg,
		Successful: !failed,
		Message:    message,
	}
	select {
	case r.events <- event{eventPackageBuildFinished, msg}:
	default:
		log.Warn("remote reporter dropping message: PackageBuildFinished")
	}
}
