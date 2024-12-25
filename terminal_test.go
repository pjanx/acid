package main

import "testing"

// TODO(p): Add a lot more test cases.
var tests = []struct {
	push, want string
}{
	{
		"\x1bc\x1b[?7l\x1b[2J\x1b[0mSeaBIOS\r",
		"SeaBIOS\n",
	},
}

func TestTerminal(t *testing.T) {
	for _, test := range tests {
		tw := terminalWriter{}
		if _, err := tw.Write([]byte(test.push)); err != nil {
			t.Errorf("%#v: %s", test.push, err)
			continue
		}
		have := string(tw.Serialize(0))
		if have != test.want {
			t.Errorf("%#v: %#v; want %#v", test.push, have, test.want)
		}
	}
}

func TestTerminalExploded(t *testing.T) {
Loop:
	for _, test := range tests {
		tw := terminalWriter{}
		for _, b := range []byte(test.push) {
			if _, err := tw.Write([]byte{b}); err != nil {
				t.Errorf("%#v: %s", test.push, err)
				continue Loop
			}
		}
		have := string(tw.Serialize(0))
		if have != test.want {
			t.Errorf("%#v: %#v; want %#v", test.push, have, test.want)
		}
	}
}
