package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/dgraph-io/badger/v2"
	"github.com/typefox/leeway/pkg/remotereporter"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NewStatsReader creates a new stats reader
func NewStatsReader(db *badger.DB) (*StatsReader, error) {
	return &StatsReader{
		db: db,
	}, nil
}

// StatsReader provices access to previously collected stats
type StatsReader struct {
	Prefix string

	db *badger.DB
}

// DurationSamples returns the samples collected for a package
func (r *StatsReader) DurationSamples(ctx context.Context, req *remotereporter.DurationSamplesRequest) (*remotereporter.DurationSamplesResponse, error) {
	res, err := r.readSamples(req.Package)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot read samples: %q", err)
	}

	return &remotereporter.DurationSamplesResponse{
		Samples: res,
	}, nil
}

func (r *StatsReader) readSamples(pkg string) ([]int64, error) {
	var res []int64
	err := r.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte(fmt.Sprintf(fmtPkgDurationSample, r.Prefix, pkg, ""))
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			err := it.Item().Value(func(v []byte) error {
				res = append(res, int64(binary.LittleEndian.Uint64(v)))
				return nil
			})
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// EstimateDuration provides a maximum likelyhood estimate of the package's build time.
func (r *StatsReader) EstimateDuration(ctx context.Context, req *remotereporter.EstimateDurationRequest) (*remotereporter.EstimateDurationResponse, error) {
	type P struct {
		Duration *remotereporter.PackageBuildDuration
		Depth    int
	}

	idx := make(map[string]*P)
	var down func(pkg *remotereporter.Package, d int) error
	down = func(pkg *remotereporter.Package, d int) error {
		if pkg.Status == remotereporter.PackageStatus_Built {
			return nil
		}
		p := idx[pkg.Metadata.Fullname]
		if p == nil {
			est, err := r.gausianEstimator(ctx, pkg.Metadata.Fullname)
			if err != nil {
				return err
			}
			p = &P{est, d}
			idx[pkg.Metadata.Fullname] = p
		}
		if p.Depth < d {
			p.Depth = d
		}

		for _, dep := range pkg.Dependencies {
			err := down(dep, d+1)
			if err != nil {
				return err
			}
		}

		return nil
	}

	err := down(req.Package, 0)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot compute estimate: %q", err.Error())
	}

	// TODO(cw): estimate total duration based on critical path

	var res remotereporter.EstimateDurationResponse
	res.Packages = make([]*remotereporter.PackageBuildDuration, 0, len(idx))
	for _, est := range idx {
		res.Packages = append(res.Packages, est.Duration)
	}

	return &res, nil
}

func (r *StatsReader) gausianEstimator(ctx context.Context, pkg string) (res *remotereporter.PackageBuildDuration, err error) {
	samples, err := r.readSamples(pkg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot read samples: %q", err)
	}

	// naively assume the data is normally distributed and fit to that distribution
	var (
		mean   float64
		stddev float64
	)
	for n, s := range samples {
		xk := float64(s)
		m := mean + (xk-mean)/float64(n+1)
		stddev = stddev + (xk-mean)*(xk-m)
		mean = m
	}

	n95 := 1.96 * (stddev / math.Sqrt(float64(len(samples))))
	return &remotereporter.PackageBuildDuration{
		Package:    pkg,
		MostLikely: int64(mean),
		N95Low:     int64(mean - n95),
		N95High:    int64(mean + n95),
	}, nil
}
