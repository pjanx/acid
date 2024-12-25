package main

import "testing"

// This could be way more extensive, but we're not aiming for perfection.
var tests = []struct {
	push, want string
}{
	{
		// Escaping and UTF-8.
		"\x03\x1bž\bř",
		"^C^[ř\n",
	},
	{
		// Several kinds of sequences to be ignored.
		"\x1bc\x1b[?7l\x1b[2J\x1b[0;1mSeaBIOS\rTea",
		"TeaBIOS\n",
	},
	{
		// New origin and absolute positioning.
		"Line 1\n\x1bcWine B\nFine 3\x1b[1;6H2\x1b[HL\nL",
		"Line 1\nLine 2\nLine 3\n",
	},
	{
		// In-line positioning (without corner cases).
		"A\x1b[CB\x1b[2C?\x1b[DC\x1b[2D\b->",
		"A B->C\n",
	},
	{
		// Up and down.
		"\nB\x1bMA\v\vC" + "\x1b[4EG" + "\x1b[FF" + "\x1b[2FD" + "\x1b[EE",
		" A\nB\nC\nD\nE\nF\nG\n",
	},
	{
		// In-line erasing.
		"1234\b\b\x1b[K\n5678\b\b\x1b[0K\n" + "abcd\b\b\x1b[1K\nefgh\x1b[2K",
		"12\n56\n  cd\n\n",
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
