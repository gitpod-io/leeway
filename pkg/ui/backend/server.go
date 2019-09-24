package backend

import (
	// "github.com/improbable-eng/grpc-web/go/grpcweb"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"github.com/typefox/leeway/pkg/remotereporter"
	"github.com/typefox/leeway/pkg/ui/backend/uiprotocol"

	rice "github.com/GeertJohan/go.rice"
	log "github.com/sirupsen/logrus"
	"github.com/soheilhy/cmux"
	"google.golang.org/grpc"
)

// NewServer creates a new UI server
func NewServer() (*Server, error) {
	return &Server{
		cond: sync.NewCond(&sync.Mutex{}),
	}, nil
}

// Server acts as remotereporter receiver and distributes the events it receives to all its clients
type Server struct {
	latestEvent *uiprotocol.BuildEvent
	cond        *sync.Cond
}

// Serve starts listening on the given address. This address can be used as remotereporter target, but also
// serves the UI and grpc-web.
func (s *Server) Serve(addr string) (err error) {
	// Create the main listener.
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	m := cmux.New(l)
	grpcwebL := m.Match(cmux.HTTP1HeaderField("x-grpc-web", "1"))
	grpcL := m.MatchWithWriters(cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"))
	httpL := m.Match(cmux.HTTP1Fast())

	grpcS := grpc.NewServer()
	remotereporter.RegisterReporterServer(grpcS, s)

	grpcwebS := grpc.NewServer()
	uiprotocol.RegisterBuildEventSourceServer(grpcwebS, s)
	wrappedGrpc := grpcweb.WrapServer(grpcwebS)
	grpcwebHTTPS := &http.Server{
		Handler: wrappedGrpc,
	}

	mux := http.NewServeMux()
	fs := http.FileServer(rice.MustFindBox("../frontend").HTTPBox())
	mux.Handle("/", http.StripPrefix("/", fs))

	httpS := &http.Server{
		Handler: mux,
	}

	go grpcS.Serve(grpcL)
	go grpcwebHTTPS.Serve(grpcwebL)
	go httpS.Serve(httpL)

	return m.Serve()
}

// Register implements uiprotocol.BuildEventSourceServer
func (s *Server) Register(req *uiprotocol.RegisterReq, client uiprotocol.BuildEventSource_RegisterServer) error {
	log.Debug("new client")
	defer log.Debug("client gone")

	for {
		s.cond.L.Lock()
		s.cond.Wait()
		err := client.Send(s.latestEvent)
		s.cond.L.Unlock()

		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (s *Server) emitEvent(evt *uiprotocol.BuildEvent) {
	s.cond.L.Lock()
	s.latestEvent = evt
	s.cond.Broadcast()
	s.cond.L.Unlock()
}

// BuildStarted implements remotereporter.ReporterServer
func (s *Server) BuildStarted(ctx context.Context, evt *remotereporter.BuildStartedEvent) (*remotereporter.BuildStartedResponse, error) {
	s.emitEvent(&uiprotocol.BuildEvent{
		Event: &uiprotocol.BuildEvent_BuildStarted{
			BuildStarted: evt,
		},
	})

	session := fmt.Sprintf("%s.%s.%d", evt.Package.Metadata.Fullname, evt.Package.Metadata.Version, time.Now().Unix())
	return &remotereporter.BuildStartedResponse{
		Session: session,
	}, nil
}

// BuildFinished implements remotereporter.ReporterServer
func (s *Server) BuildFinished(ctx context.Context, evt *remotereporter.BuildFinishedEvent) (*remotereporter.NoResponse, error) {
	s.emitEvent((&uiprotocol.BuildEvent{
		Event: &uiprotocol.BuildEvent_BuildFinished{
			BuildFinished: evt,
		},
	}))
	return &remotereporter.NoResponse{}, nil
}

// PackageBuildStarted implements remotereporter.ReporterServer
func (s *Server) PackageBuildStarted(ctx context.Context, evt *remotereporter.PackageBuildStartedEvent) (*remotereporter.NoResponse, error) {
	s.emitEvent((&uiprotocol.BuildEvent{
		Event: &uiprotocol.BuildEvent_PackageBuildStarted{
			PackageBuildStarted: evt,
		},
	}))
	return &remotereporter.NoResponse{}, nil
}

// PackageBuildLog implements remotereporter.ReporterServer
func (s *Server) PackageBuildLog(inc remotereporter.Reporter_PackageBuildLogServer) error {
	var err error
	for msg, err := inc.Recv(); msg != nil && err == nil; msg, err = inc.Recv() {
		s.emitEvent((&uiprotocol.BuildEvent{
			Event: &uiprotocol.BuildEvent_BuildLog{
				BuildLog: msg,
			},
		}))
	}
	return err
}

// PackageBuildFinished implements remotereporter.ReporterServer
func (s *Server) PackageBuildFinished(ctx context.Context, evt *remotereporter.PackageBuildFinishedEvent) (*remotereporter.NoResponse, error) {
	s.emitEvent((&uiprotocol.BuildEvent{
		Event: &uiprotocol.BuildEvent_PackageBuildFinished{
			PackageBuildFinished: evt,
		},
	}))
	return &remotereporter.NoResponse{}, nil
}
