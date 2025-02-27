package provutil

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gitpod-io/leeway/pkg/leeway"
	"github.com/in-toto/in-toto-golang/in_toto"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/bom/pkg/provenance"
)

type Assertion struct {
	Name        string
	Description string
	Run         func(stmt *provenance.Statement) []Violation
	RunBundle   func(bundle *provenance.Envelope) []Violation
}

type Violation struct {
	Assertion *Assertion
	Statement *provenance.Statement
	Desc      string
}

func (v Violation) String() string {
	if v.Statement == nil {
		return fmt.Sprintf("failed %s: %s", v.Assertion.Name, v.Desc)
	}

	pred := v.Statement.Predicate
	return fmt.Sprintf("%s failed %s: %s", pred.Invocation.ConfigSource.EntryPoint, v.Assertion.Name, v.Desc)
}

type Assertions []*Assertion

func (a Assertions) AssertBundle(bundle *provenance.Envelope) (failed []Violation) {
	for _, as := range a {
		if as.RunBundle == nil {
			continue
		}

		res := as.RunBundle(bundle)
		for i := range res {
			res[i].Assertion = as
		}
		failed = append(failed, res...)
	}
	return
}

func (a Assertions) AssertStatement(stmt *provenance.Statement) (failed []Violation) {
	// we must not keep a reference to stmt around - it will change for each invocation
	s := *stmt
	for _, as := range a {
		if as.Run == nil {
			continue
		}

		res := as.Run(stmt)
		for i := range res {
			res[i].Statement = &s
			res[i].Assertion = as
		}
		failed = append(failed, res...)
	}
	return
}

var AssertBuiltWithLeeway = &Assertion{
	Name:        "built-with-leeway",
	Description: "ensures all bundle entries have been built with leeway",
	Run: func(stmt *provenance.Statement) []Violation {
		pred := stmt.Predicate
		if strings.HasPrefix(pred.Builder.ID, leeway.ProvenanceBuilderID) {
			return nil
		}

		return []Violation{
			{Desc: "was not built using leeway"},
		}
	},
}

func AssertBuiltWithLeewayVersion(version string) *Assertion {
	return &Assertion{
		Name:        "built-with-leeway-version",
		Description: "ensures all bundle entries which have been built using leeway, used version " + version,
		Run: func(stmt *provenance.Statement) []Violation {
			pred := stmt.Predicate
			if !strings.HasPrefix(pred.Builder.ID, leeway.ProvenanceBuilderID) {
				return nil
			}

			if pred.Builder.ID != leeway.ProvenanceBuilderID+":"+version {
				return []Violation{{Desc: "was built using leeway version " + strings.TrimPrefix(pred.Builder.ID, leeway.ProvenanceBuilderID+":")}}
			}

			return nil
		},
	}
}

var AssertGitMaterialOnly = &Assertion{
	Name:        "git-material-only",
	Description: "ensures all subjects were built from Git material only",
	Run: func(stmt *provenance.Statement) []Violation {
		pred := stmt.Predicate
		for _, m := range pred.Materials {
			if strings.HasPrefix(m.URI, "git+") || strings.HasPrefix(m.URI, "git://") {
				continue
			}

			return []Violation{{
				Desc: "contains non-Git material, e.g. " + m.URI,
			}}
		}
		return nil
	},
}

func AssertSignedWith(key in_toto.Key) *Assertion {
	return &Assertion{
		Name:        "signed-with",
		Description: "ensures all bundles are signed with the given key",
		RunBundle: func(bundle *provenance.Envelope) []Violation {
			for _, s := range bundle.Signatures {
				raw, err := json.Marshal(s)
				if err != nil {
					return []Violation{{Desc: "assertion error: " + err.Error()}}
				}
				var sig in_toto.Signature
				err = json.Unmarshal(raw, &sig)
				if err != nil {
					return []Violation{{Desc: "assertion error: " + err.Error()}}
				}

				err = in_toto.VerifySignature(key, sig, []byte(bundle.Payload))
				if err != nil {
					log.WithError(err).WithField("signature", sig).Debug("signature does not match")
					continue
				}

				return nil
			}
			return []Violation{{Desc: "not signed with the given key"}}
		},
	}
}
