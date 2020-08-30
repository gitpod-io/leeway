module github.com/typefox/leeway/extra/stats-collector

go 1.15

replace github.com/typefox/leeway => ../..

require (
	github.com/dgraph-io/badger/v2 v2.2007.1
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/typefox/leeway v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.31.1
	google.golang.org/protobuf v1.23.0
)
