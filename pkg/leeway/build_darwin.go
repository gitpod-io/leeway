package leeway

import (
	"fmt"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

func checkForCpCompatibility() error {
	out, err := exec.Command("cp", "--help").CombinedOutput()
	if err != nil && !strings.Contains(err.Error(), "exit") {
		log.WithError(err).Debug("cannot check if cp is compatible")
		// if cp is not compatible we'll fail later in the build,
		// but maybe it is and we don't want to fail here for no good reason.
		return nil
	}

	if strings.Contains(string(out), "--parents") {
		// we're good
		return nil
	}

	return fmt.Errorf("leeway requires a GNU-compatible cp. Please install using `brew install coreutils`; make sure you update your PATH after installing.")
}

func executeCommandsForPackageSafe(buildctx *buildContext, p *Package, wd string, commands [][]string) error {
	return fmt.Errorf("not implemented")
}
