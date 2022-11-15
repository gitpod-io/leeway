package leeway

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseGSUTilStat(t *testing.T) {
	output := `
		gs://gitpod-core-leeway-cache-branch/232bbf468ca410aabddb02037a4297eebf828940.tar.gz:
			Creation time:          Wed, 02 Nov 2022 06:36:45 GMT
			Update time:            Wed, 02 Nov 2022 06:36:45 GMT
			Storage class:          STANDARD
			Content-Length:         10773682
			Content-Type:           application/x-tar
			Hash (crc32c):          ieKrSw==
			Hash (md5):             Tb3dpUJTpG70KaaJcrxiZw==
			ETag:                   CNnukYTxjvsCEAE=
			Generation:             1667371005933401
			Metageneration:         1
		gs://gitpod-core-leeway-cache-branch/232bbf468ca410aabddb02037a4297eebf828941.tar.gz:
			Creation time:          Wed, 02 Nov 2022 06:36:45 GMT
			Update time:            Wed, 02 Nov 2022 06:36:45 GMT
			Storage class:          STANDARD
			Content-Length:         10773682
			Content-Type:           application/x-tar
			Hash (crc32c):          ieKrSw==
			Hash (md5):             Tb3dpUJTpG70KaaJcrxiZw==
			ETag:                   CNnukYTxjvsCEAE=
		No URLs matched: gs://gitpod-core-leeway-cache-branch/232bbf468ca410aabddb02037a4297eebf828943.tar.gz
		No URLs matched: gs://gitpod-core-leeway-cache-branch/232bbf468ca410aabddb02037a4297eebf8289434.tar.gz
			Generation:             1667371005933401
			Metageneration:         1
	`
	output = strings.Replace(output, "\t\t", "", -1)
	expected := map[string]struct{}{
		"gs://gitpod-core-leeway-cache-branch/232bbf468ca410aabddb02037a4297eebf828940.tar.gz": {},
		"gs://gitpod-core-leeway-cache-branch/232bbf468ca410aabddb02037a4297eebf828941.tar.gz": {},
	}
	actual := parseGSUtilStatOutput(strings.NewReader(output))

	if diff := cmp.Diff(expected, actual); diff != "" {
		t.Errorf("TestParseGSUTilStat() mismatch (-want +got):\n%s", diff)
	}
}
