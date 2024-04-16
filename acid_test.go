package main

import (
	"bytes"
	"testing"
	ttemplate "text/template"
)

func TestTemplateQuote(t *testing.T) {
	// Ideally, we should back-parse it using sh syntax.
	// This is an unnecessarily fragile test.
	for _, test := range []struct {
		input, output string
	}{
		{`!!'!$`, `'!!'\''!$'`},
		{``, `""`},
		{`${var}`, `"\${var}"`},
		{"`cat`", "\"\\`cat\\`\""},
		{`"魚\"`, `"\"魚\\\""`},
	} {
		var b bytes.Buffer
		err := ttemplate.Must(ttemplate.New("test").
			Funcs(shellFuncs).Parse("{{quote .}}")).Execute(&b, test.input)
		if err != nil {
			t.Errorf("template execution error: %s\n", err)
		}
		if b.String() != test.output {
			t.Errorf("%q should be quoted os %q, not %q\n",
				test.input, test.output, b.String())
		}
	}
}
