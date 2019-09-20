package remotereporter

import (
	context "context"
	fmt "fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

// Receiver is the receiving end for a remote reporter
type Receiver struct{}

func metadataToFields(session string, m *PackageMetadata) log.Fields {
	return log.Fields{
		"session": session,
		"package": m.Fullname,
		"version": m.Version,
	}
}

// BuildStarted is called when a new build was started
func (r *Receiver) BuildStarted(ctx context.Context, evt *BuildStartedEvent) (*BuildStartedResponse, error) {
	session := fmt.Sprintf("%s.%s.%d", evt.Package.Metadata.Fullname, evt.Package.Metadata.Version, time.Now().Unix())
	log.WithFields(metadataToFields(session, evt.Package.Metadata)).Info("build started")
	return &BuildStartedResponse{
		Session: session,
	}, nil
}

// BuildFinished is called when a build has finished
func (r *Receiver) BuildFinished(ctx context.Context, evt *BuildFinishedEvent) (*NoResponse, error) {
	log.WithFields(metadataToFields(evt.Session, evt.Package)).Info("build finished")
	return &NoResponse{}, nil
}

// PackageBuildStarted is called when a package build has finished
func (r *Receiver) PackageBuildStarted(ctx context.Context, evt *PackageBuildStartedEvent) (*NoResponse, error) {
	log.WithFields(metadataToFields(evt.Session, evt.Package)).Info("pkg build started")
	return &NoResponse{}, nil
}

// PackageBuildLog is called for reporting build output
func (r *Receiver) PackageBuildLog(inc Reporter_PackageBuildLogServer) error {
	var err error
	for msg, err := inc.Recv(); msg != nil && err == nil; msg, err = inc.Recv() {
		log.WithFields(metadataToFields(msg.Session, msg.Package)).WithField("data", string(msg.Data)).Info("log")
	}

	return err
}

// PackageBuildFinished is called when a package has been built
func (r *Receiver) PackageBuildFinished(ctx context.Context, evt *PackageBuildFinishedEvent) (*NoResponse, error) {
	log.WithFields(metadataToFields(evt.Session, evt.Package)).Info("pkg build finished")
	return &NoResponse{}, nil
}
