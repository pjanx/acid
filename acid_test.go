package main

import (
	"bytes"
	"testing"
	ttemplate "text/template"
	"time"
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

func TestShortDurationString(t *testing.T) {
	for _, test := range []struct {
		d      time.Duration
		expect string
	}{
		{72 * time.Hour, "3d"},
		{-3 * time.Hour, "-3h"},
		{12 * time.Minute, "12m"},
		{time.Millisecond, "0s"},
	} {
		if sd := shortDurationString(test.d); sd != test.expect {
			t.Errorf("%s = %s; want %s\n", test.d, sd, test.expect)
		}
	}
}
