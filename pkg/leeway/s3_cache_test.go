package leeway

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/mock/gomock"

	"github.com/gitpod-io/leeway/pkg/leeway/mocks"
)

func TestNewS3RemoteCache(t *testing.T) {
	ctx := context.Background()

	t.Run("with valid config", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		mockS3Client := mocks.NewMockS3Client(ctrl)
		mockSTSClient := mocks.NewMockSTSClient(ctrl)

		mockSTSClient.EXPECT().GetCallerIdentity(gomock.Any(), gomock.Any()).Return(&sts.GetCallerIdentityOutput{
			Account: aws.String("123456789012"),
			Arn:     aws.String("arn:aws:iam::123456789012:user/TestUser"),
			UserId:  aws.String("TESTUSERID"),
		}, nil)

		cache, err := NewS3RemoteCache(ctx, "test-bucket", mockS3Client, mockSTSClient)
		if err != nil {
			t.Fatalf("NewS3RemoteCache() error = %v", err)
		}
		if cache == nil {
			t.Fatal("NewS3RemoteCache() returned nil cache")
		}
		if diff := cmp.Diff("test-bucket", cache.config.BucketName); diff != "" {
			t.Errorf("BucketName mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestS3RemoteCache_ExistingPackages(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockS3Client := mocks.NewMockS3Client(ctrl)
	mockSTSClient := mocks.NewMockSTSClient(ctrl)

	cache := &S3RemoteCache{
		config: S3Config{
			BucketName: "test-bucket",
		},
		s3Client:  mockS3Client,
		stsClient: mockSTSClient,
	}

	// Create test packages
	pkg1 := NewTestPackage("pkg1")
	pkg2 := NewTestPackage("pkg2")
	pkg3 := NewTestPackage("pkg3")

	pkgs := []*Package{pkg1, pkg2, pkg3}

	// Set up mock expectations
	mockS3Client.EXPECT().HeadObject(gomock.Any(), gomock.Any()).Return(&s3.HeadObjectOutput{}, nil)
	mockS3Client.EXPECT().HeadObject(gomock.Any(), gomock.Any()).Return(&s3.HeadObjectOutput{}, nil)
	mockS3Client.EXPECT().HeadObject(gomock.Any(), gomock.Any()).Return(nil, &types.NoSuchKey{})

	existingPkgs, err := cache.ExistingPackages(ctx, pkgs)
	if err != nil {
		t.Fatalf("ExistingPackages() error = %v", err)
	}

	expectedPkgs := map[*Package]struct{}{
		pkg1: {},
		pkg2: {},
	}

	if diff := cmp.Diff(expectedPkgs, existingPkgs, cmp.AllowUnexported(Package{})); diff != "" {
		t.Errorf("ExistingPackages() mismatch (-want +got):\n%s", diff)
	}
}
