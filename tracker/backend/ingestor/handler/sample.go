package handler

import (
	context "context"
	"strconv"
	"time"

	"github.com/InfluxCommunity/influxdb3-go/influx"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	v1 "github.com/gitpod-io/leeway/pkg/remotereporter/api/gen/v1"
	segment "github.com/segmentio/analytics-go/v3"
	"github.com/sirupsen/logrus"
)

type PackageSample struct {
	FullName         string
	DirtyWorkingCopy bool
	Type             v1.PackageType
	Status           PackageStatus
	Time             time.Time
	BuildDuration    time.Duration
}

type PackageStatus string

const (
	PackageStatusSuccess     PackageStatus = "success"
	PackageStatusFailed      PackageStatus = "failed"
	PackageStatusFailedTests PackageStatus = "failed_tests"
)

type SampleStorageFunc func(ctx context.Context, sample *v1.PackageBuildFinishedRequest) error

func PrintSample(ctx context.Context, sample *v1.PackageBuildFinishedRequest) error {
	logrus.WithField("sample", sample).Info("package sample")
	return nil
}

func PutCloudwatchMetric(cw *cloudwatch.Client) SampleStorageFunc {
	return func(ctx context.Context, sample *v1.PackageBuildFinishedRequest) error {
		_, err := cw.PutMetricData(ctx, &cloudwatch.PutMetricDataInput{
			Namespace: aws.String("leeway"),
			MetricData: []types.MetricDatum{
				{
					Timestamp:  aws.Time(time.Now()),
					Value:      aws.Float64((time.Duration(sample.DurationMs) * time.Millisecond).Seconds()),
					Unit:       types.StandardUnitSeconds,
					MetricName: aws.String("package_build_duration"),
					Dimensions: []types.Dimension{
						{Name: aws.String("name"), Value: aws.String(sample.Package.Name)},
						{Name: aws.String("success"), Value: aws.String(strconv.FormatBool(sample.Error == ""))},
						{Name: aws.String("type"), Value: aws.String(sample.Package.Type.String())},
						{Name: aws.String("dirtyWorkingCopy"), Value: aws.String(strconv.FormatBool(sample.Package.Git.DirtyWorkingCopy))},
					},
				},
			},
		})
		return err
	}
}

func WriteToInfluxDB(client *influx.Client, database string) SampleStorageFunc {
	return func(ctx context.Context, sample *v1.PackageBuildFinishedRequest) error {
		return client.WritePoints(ctx, database, influx.NewPointWithMeasurement("package_build_duration").
			AddTag("name", sample.Package.Name).
			AddTag("type", sample.Package.Type.String()).
			AddTag("success", strconv.FormatBool(sample.Error == "")).
			AddTag("gitOrigin", sample.Package.Git.Origin).
			AddField("gitCommit", sample.Package.Git.Commit).
			AddField("gitDirty", sample.Package.Git.DirtyWorkingCopy).
			AddField("durationSeconds", (time.Duration(sample.DurationMs)*time.Millisecond).Seconds()),
		)
	}
}

func WriteToSegment(client segment.Client) SampleStorageFunc {
	return func(ctx context.Context, sample *v1.PackageBuildFinishedRequest) error {
		eventName := "package_build_"
		if sample.Error == "" {
			eventName += "succeeded"
		} else {
			eventName += "failed"
		}

		client.Enqueue(segment.Track{
			AnonymousId: sample.SessionId,
			Event:       eventName,
			Timestamp:   time.Now(),
			Properties: segment.Properties{
				"name":             sample.Package.Name,
				"durationMS":       sample.DurationMs,
				"repo":             sample.Package.Git.Origin,
				"dirtyWorkingCopy": sample.Package.Git.DirtyWorkingCopy,
				"commit":           sample.Package.Git.Commit,
			},
		})
		return nil
	}
}
