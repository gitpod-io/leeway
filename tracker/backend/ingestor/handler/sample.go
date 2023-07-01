package handler

import (
	context "context"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	v1 "github.com/gitpod-io/leeway/pkg/remotereporter/api/gen/v1"
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

type SampleStorageFunc func(ctx context.Context, sample PackageSample) error

func PrintSample(ctx context.Context, sample PackageSample) error {
	logrus.WithField("sample", sample).Info("package sample")
	return nil
}

func PutCloudwatchMetric(cw *cloudwatch.Client) SampleStorageFunc {
	return func(ctx context.Context, sample PackageSample) error {
		_, err := cw.PutMetricData(ctx, &cloudwatch.PutMetricDataInput{
			Namespace: aws.String("leeway"),
			MetricData: []types.MetricDatum{
				{
					Timestamp:  aws.Time(sample.Time),
					Value:      aws.Float64(sample.BuildDuration.Seconds()),
					Unit:       types.StandardUnitSeconds,
					MetricName: aws.String("package_build_duration"),
					Dimensions: []types.Dimension{
						{Name: aws.String("name"), Value: aws.String(sample.FullName)},
						{Name: aws.String("status"), Value: aws.String(string(sample.Status))},
						{Name: aws.String("type"), Value: aws.String(sample.Type.String())},
						{Name: aws.String("dirtyWorkingCopy"), Value: aws.String(strconv.FormatBool(sample.DirtyWorkingCopy))},
					},
				},
			},
		})
		return err
	}
}
