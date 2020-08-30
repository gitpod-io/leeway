package remotereporter

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/typefox/leeway/pkg/leeway"
	"google.golang.org/grpc"
)

// NewDurationEstimator produces a new duration estimator that queries a stats collector
func NewDurationEstimator(host string, opts ...grpc.DialOption) (leeway.DurationEstimator, error) {
	opts = append(opts, grpc.WithBlock())
	conn, err := grpc.Dial(host, opts...)
	if err != nil {
		return nil, err
	}

	client := NewStatsServiceClient(conn)

	return func(pkg *leeway.Package, total bool) (mostLikelyMS int64, n95Low int64, n95High int64, err error) {
		rpcpkg, err := toRPCPackage(pkg, nil)
		if err != nil {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err := client.EstimateDuration(ctx, &EstimateDurationRequest{Package: rpcpkg})
		if err != nil {
			return
		}
		log.WithField("resp", resp).WithField("pkg", pkg.FullName()).Debug("got resopnse from stats collector")

		var res *PackageBuildDuration
		if total {
			res = resp.Total
		} else {
			for _, est := range resp.Packages {
				if est.Package == pkg.FullName() {
					res = est
					break
				}
			}
		}
		if res == nil {
			err = leeway.ErrNoEstimate
			return
		}

		return res.MostLikely, res.N95Low, res.N95High, nil
	}, nil

}
