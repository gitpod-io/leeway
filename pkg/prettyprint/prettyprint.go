package prettyprint

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"text/template"

	"gopkg.in/yaml.v3"
)

// Format is an output format for pretty printing
type Format string

const (
	// TemplateFormat produces text/template-based output
	TemplateFormat Format = "template"
	// JSONFormat produces JSON output
	JSONFormat Format = "json"
	// YAMLFormat produces YAML output
	YAMLFormat Format = "yaml"
)

// Writer preconfigures the write function
type Writer struct {
	Out          io.Writer
	Format       Format
	FormatString string
}

// Write prints the input in the preconfigred way
func (w *Writer) Write(in interface{}) error {
	switch w.Format {
	case TemplateFormat:
		return writeTemplate(w.Out, in, w.FormatString)
	case JSONFormat:
		return json.NewEncoder(w.Out).Encode(in)
	case YAMLFormat:
		return yaml.NewEncoder(w.Out).Encode(in)
	default:
		return fmt.Errorf("unknown format: %s", w.Format)
	}
}

func writeTemplate(out io.Writer, in interface{}, tplc string) error {
	tpl := template.New("template")
	tpl, err := tpl.Parse(tplc)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	defer w.Flush()

	return tpl.Execute(w, in)
}
