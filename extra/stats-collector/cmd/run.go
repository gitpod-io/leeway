package cmd

import (
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/dgraph-io/badger/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/typefox/leeway/extra/stats-collector/pkg/collector"
	"github.com/typefox/leeway/pkg/remotereporter"
	"google.golang.org/grpc"
)

var runOpts struct {
	Addr string
}

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run <database-file>",
	Short: "Runs the stats collector",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		db, err := badger.Open(badger.DefaultOptions(args[0]))
		if err != nil {
			log.WithError(err).Fatal("cannot open database file")
		}
		defer db.Close()

		recorder, err := collector.NewRecorder(db)
		if err != nil {
			log.WithError(err).Fatal("cannot start recorder")
		}
		reader, err := collector.NewStatsReader(db)
		if err != nil {
			log.WithError(err).Fatal("cannot start recorder")
		}

		lis, err := net.Listen("tcp", runOpts.Addr)
		if err != nil {
			log.WithError(err).WithField("addr", runOpts.Addr).Fatal("cannot listen on address")
		}

		srv := grpc.NewServer()
		remotereporter.RegisterReporterServer(srv, recorder)
		remotereporter.RegisterStatsServiceServer(srv, reader)
		go srv.Serve(lis)

		log.Info("stats-collector is up and running")
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		log.Info("received SIGTERM, stopping")
	},
}

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.Flags().StringVarP(&runOpts.Addr, "addr", "a", ":9090", "the address where to serve the stats collector")
}
