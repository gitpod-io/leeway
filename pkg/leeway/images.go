package leeway

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"os/exec"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

type ImageAdapter interface {
	Create(imageName string) error
	Sign(imageName, profileARN string) error
}

// ECRAdapter implements the ImageAdapter interface for AWS ECR
type ECRAdapter struct {
	ecrClient *ecr.Client
}

// NewECRAdapter initializes an ECRAdapter with an AWS ECR client
func NewECRAdapter() (*ECRAdapter, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config, %v", err)
	}

	client := ecr.NewFromConfig(cfg)
	return &ECRAdapter{
		ecrClient: client,
	}, nil
}

// Create checks if the ECR image exists and creates it if it doesn't
func (e *ECRAdapter) Create(image string) error {
	imageName := getRepoNameFromImage(image)

	_, err := e.ecrClient.DescribeImages(context.TODO(), &ecr.DescribeImagesInput{
		RepositoryName: aws.String(imageName),
	})
	if err == nil {
		fmt.Printf("Image %s already exists\n", imageName)
		return nil
	}

	if !isRepositoryNotFoundErr(err) {
		return fmt.Errorf("failed to check if ECR image %s exists: %w", imageName, err)
	}

	_, err = e.ecrClient.CreateRepository(context.TODO(), &ecr.CreateRepositoryInput{
		RepositoryName: aws.String(imageName),
	})
	if err != nil {
		return fmt.Errorf("failed to create ECR image: %w", err)
	}

	fmt.Printf("Image %s created successfully\n", imageName)
	return nil
}

// Sign uses the notation tool to sign the ECR image
func (e *ECRAdapter) Sign(imageName, profileARN string) error {
	cmd := exec.Command("notation", "sign", "--profile", profileARN, imageName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to sign the image: %v, output: %s", err, string(output))
	}

	fmt.Printf("Image %s signed successfully\n", imageName)
	return nil
}

// isImageNotFoundErr checks if the error is an ImageNotFoundException
func isRepositoryNotFoundErr(err error) bool {
	var notFoundErr *types.RepositoryNotFoundException
	return errors.As(err, &notFoundErr)
}

// getRepoNameFromImage extracts and returns the full repository name from the image string.
func getRepoNameFromImage(image string) string {
	// Split the image string by slashes
	parts := strings.Split(image, "/")
	// Combine the parts after the domain name to get the full repository name
	repoName := strings.Join(parts[1:], "/")
	// Split the repo name by colon to remove the tag if present
	repoParts := strings.Split(repoName, ":")
	// Return the first part, which is the full repo name without the tag
	return repoParts[0]
}
