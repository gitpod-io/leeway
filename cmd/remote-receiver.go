package cmd

import (
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/typefox/leeway/pkg/remotereporter"
	"google.golang.org/grpc"
)

// collectCmd represents the collect command
var remoteReceiverCmd = &cobra.Command{
	Use:   "remote-receiver <address>",
	Short: "Starts a remote reporter endpoint which logs to the console",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		lis, err := net.Listen("tcp", args[0])
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}
		grpcServer := grpc.NewServer()
		remotereporter.RegisterReporterServer(grpcServer, &remotereporter.Receiver{})
		grpcServer.Serve(lis)
	},
}

func init() {
	rootCmd.AddCommand(remoteReceiverCmd)
}
