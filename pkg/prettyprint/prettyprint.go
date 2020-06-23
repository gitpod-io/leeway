package prettyprint

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"text/template"

	"gopkg.in/yaml.v2"
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
	return Write(w.Out, in, w.Format, w.FormatString)
}

// Write prints an input value using the format to the writer
func Write(out io.Writer, in interface{}, format Format, formatString string) error {
	switch format {
	case TemplateFormat:
		return writeTemplate(out, in, formatString)
	case JSONFormat:
		return json.NewEncoder(out).Encode(in)
	case YAMLFormat:
		return yaml.NewEncoder(out).Encode(in)
	default:
		return fmt.Errorf("unknown format: %s", format)
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
