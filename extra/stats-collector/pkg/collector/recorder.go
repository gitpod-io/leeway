package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v2"
	log "github.com/sirupsen/logrus"
	"github.com/typefox/leeway/pkg/remotereporter"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var (
	seqEventClock = []byte("build-events")

	fmtRawEvent          = "%sevt.%s.%s.%020d"
	fmtPkgDurationSample = "%spkg.t.%s.%s"
)

// NewRecorder produces a new build event recorder
func NewRecorder(db *badger.DB) (*Recorder, error) {
	seq, err := db.GetSequence(seqEventClock, 10)
	if err != nil {
		return nil, fmt.Errorf("cannot create event sequence: %w", err)
	}
	return &Recorder{
		db:       db,
		evtClock: seq,
	}, nil
}

// Recorder records build events in a badger DB
type Recorder struct {
	Prefix   string
	db       *badger.DB
	evtClock *badger.Sequence
}

// BuildStarted records the event
func (r *Recorder) BuildStarted(ctx context.Context, evt *remotereporter.BuildStartedEvent) (resp *remotereporter.BuildStartedResponse, err error) {
	tick, err := r.evtClock.Next()
	if err != nil {
		log.WithError(err).Error("cannot get next event clock tick")
		return nil, status.Error(codes.Internal, "cannot get next event clock tick")
	}

	return &remotereporter.BuildStartedResponse{
		Session: fmt.Sprintf("sess-%03d", tick),
	}, nil
}

// BuildFinished records the event
func (r *Recorder) BuildFinished(context.Context, *remotereporter.BuildFinishedEvent) (*remotereporter.NoResponse, error) {
	return &remotereporter.NoResponse{}, nil
}

// PackageBuildLog does nothing
func (r *Recorder) PackageBuildLog(remotereporter.Reporter_PackageBuildLogServer) error {
	return nil
}

// PackageBuildStarted records the event
func (r *Recorder) PackageBuildStarted(ctx context.Context, evt *remotereporter.PackageBuildStartedEvent) (*remotereporter.NoResponse, error) {
	err := r.recordEvent("start", evt.Package.Fullname, evt)
	if err != nil {
		return nil, err
	}
	return &remotereporter.NoResponse{}, nil
}

// PackageBuildFinished records the event
func (r *Recorder) PackageBuildFinished(ctx context.Context, evt *remotereporter.PackageBuildFinishedEvent) (*remotereporter.NoResponse, error) {
	err := r.recordEvent("start", evt.Package.Fullname, evt)
	if err != nil {
		return nil, err
	}
	key := fmt.Sprintf(fmtPkgDurationSample, r.Prefix, evt.Package.Fullname, time.Now().Format(time.RFC3339Nano))

	err = r.db.Update(func(txn *badger.Txn) error {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, uint64(evt.DurationMilliseconds))
		return txn.Set([]byte(key), b)
	})
	if err != nil {
		log.WithError(err).Error("cannot store package build time sample")
	}
	log.WithFields(log.Fields{
		"key": key,
		"t":   evt.DurationMilliseconds,
	}).Debug("new package sample")

	return &remotereporter.NoResponse{}, nil
}

func (r *Recorder) recordEvent(evtnme, pkgnme string, evt proto.Message) error {
	rb, err := proto.Marshal(evt)
	if err != nil {
		log.WithError(err).Error("cannot remarshal message")
		return status.Error(codes.InvalidArgument, "cannot remarshal message")
	}
	tick, err := r.evtClock.Next()
	if err != nil {
		log.WithError(err).Error("cannot get next event clock tick")
		return status.Error(codes.Internal, "cannot get next event clock tick")
	}
	err = r.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(fmt.Sprintf("%sevt.%s.%s.%020d", r.Prefix, pkgnme, evtnme, tick)), rb)
	})
	if err != nil {
		log.WithError(err).Error("cannot record event")
		return status.Error(codes.Internal, "cannot record event")
	}
	return nil
}
