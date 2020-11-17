package cmd

import (
	"context"
	"time"

	"github.com/containerd/containerd/remotes/docker"
	"github.com/spf13/cobra"
	"github.com/typefox/leeway/pkg/retag"
)

// describeCmd represents the describe command
var internalRetagCmd = &cobra.Command{
	Use:   "retag <old-ref> <new-ref>",
	Short: "Retags a Docker image",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		return retag.CopyManifest(ctx, docker.NewResolver(docker.ResolverOptions{
			Authorizer: docker.NewDockerAuthorizer(docker.WithAuthCreds(func(s string) (username string, secret string, err error) {
				// somehow we need to load the Docker auth without pulling half of Docker as dependency
				return
			})),
		}), args[0], args[1])
	},
}

func init() {
	internalCmd.AddCommand(internalRetagCmd)
}
