package main

import (
	"bytes"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

type terminalLine struct {
	// For simplicity, we assume that all runes take up one cell,
	// including TAB and non-spacing ones.
	// The next step would be grouping non-spacing characters,
	// in particular Unicode modifier letters, with their base.
	columns []rune

	// updateGroup is the topmost line that has changed since this line
	// has appeared, for the purpose of update tracking.
	updateGroup int
}

// terminalWriter does a best-effort approximation of an infinite-size
// virtual terminal.
type terminalWriter struct {
	sync.Mutex
	Tee   io.WriteCloser
	lines []terminalLine

	// Zero-based coordinates within lines.
	column, line int

	// lineTop is used as the base for positioning commands.
	lineTop int

	written    int
	byteBuffer []byte
	runeBuffer []rune
}

func (tw *terminalWriter) log(format string, v ...interface{}) {
	if os.Getenv("ACID_TERMINAL_DEBUG") != "" {
		log.Printf("terminal: "+format+"\n", v...)
	}
}

func (tw *terminalWriter) Serialize(top int) []byte {
	var b bytes.Buffer
	for i := top; i < len(tw.lines); i++ {
		b.WriteString(string(tw.lines[i].columns))
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func (tw *terminalWriter) Write(p []byte) (written int, err error) {
	tw.Lock()
	defer tw.Unlock()

	// TODO(p): Rather use io.MultiWriter?
	// Though I'm not sure what to do about closing (FD leaks).
	// Eventually, any handles would be garbage collected in any case.
	if tw.Tee != nil {
		tw.Tee.Write(p)
	}

	// Enough is enough, writing too much is highly suspicious.
	ok, remaining := true, 64<<20-tw.written
	if remaining < 0 {
		ok, p = false, nil
	} else if remaining < len(p) {
		ok, p = false, p[:remaining]
	}
	tw.written += len(p)

	// By now, more or less everything should run in UTF-8.
	//
	// This might have better performance with a ring buffer,
	// so as to avoid reallocations.
	b := append(tw.byteBuffer, p...)
	if !ok {
		b = append(b, "\nToo much terminal output\n"...)
	}
	for utf8.FullRune(b) {
		r, len := utf8.DecodeRune(b)
		b, tw.runeBuffer = b[len:], append(tw.runeBuffer, r)
	}
	tw.byteBuffer = b
	for tw.processRunes() {
	}
	return len(p), nil
}

func (tw *terminalWriter) processPrint(r rune) {
	// Extend the buffer vertically.
	for len(tw.lines) <= tw.line {
		tw.lines = append(tw.lines,
			terminalLine{updateGroup: len(tw.lines)})
	}

	// Refresh update trackers, if necessary.
	if tw.lines[len(tw.lines)-1].updateGroup > tw.line {
		for i := tw.line; i < len(tw.lines); i++ {
			tw.lines[i].updateGroup = tw.line
		}
	}

	// Emulate `cat -v` for C0 characters.
	seq := make([]rune, 0, 2)
	if r < 32 && r != '\t' {
		seq = append(seq, '^', 64+r)
	} else {
		seq = append(seq, r)
	}

	// Extend the line horizontally and write the rune.
	for _, r := range seq {
		line := &tw.lines[tw.line]
		for len(line.columns) <= tw.column {
			line.columns = append(line.columns, ' ')
		}

		line.columns[tw.column] = r
		tw.column++
	}
}

func (tw *terminalWriter) processFlush() {
	tw.column = 0
	tw.line = len(tw.lines)
	tw.lineTop = tw.line
}

func (tw *terminalWriter) processParsedCSI(
	private rune, param, intermediate []rune, final rune) bool {
	var params []int
	if len(param) > 0 {
		for _, p := range strings.Split(string(param), ";") {
			i, _ := strconv.Atoi(p)
			params = append(params, i)
		}
	}

	if private == '?' && len(intermediate) == 0 &&
		(final == 'h' || final == 'l') {
		for _, p := range params {
			// 25 (DECTCEM): There is no cursor to show or hide.
			// 7 (DECAWM): We cannot wrap, we're infinite.
			if !(p == 25 || (p == 7 && final == 'l')) {
				return false
			}
		}
		return true
	}
	if private != 0 || len(intermediate) > 0 {
		return false
	}

	switch {
	case final == 'C': // Cursor Forward
		if len(params) == 0 {
			tw.column++
		} else if len(params) >= 1 {
			tw.column += params[0]
		}
		return true
	case final == 'D': // Cursor Backward
		if len(params) == 0 {
			tw.column--
		} else if len(params) >= 1 {
			tw.column -= params[0]
		}
		if tw.column < 0 {
			tw.column = 0
		}
		return true
	case final == 'E': // Cursor Next Line
		if len(params) == 0 {
			tw.line++
		} else if len(params) >= 1 {
			tw.line += params[0]
		}
		tw.column = 0
		return true
	case final == 'F': // Cursor Preceding Line
		if len(params) == 0 {
			tw.line--
		} else if len(params) >= 1 {
			tw.line -= params[0]
		}
		if tw.line < tw.lineTop {
			tw.line = tw.lineTop
		}
		tw.column = 0
		return true
	case final == 'H': // Cursor Position
		if len(params) == 0 {
			tw.line = tw.lineTop
			tw.column = 0
		} else if len(params) >= 2 && params[0] != 0 && params[1] != 0 {
			tw.line = tw.lineTop + params[0] - 1
			tw.column = params[1] - 1
		} else {
			return false
		}
		return true
	case final == 'J': // Erase in Display
		if len(params) == 0 || params[0] == 0 || params[0] == 2 {
			// We're not going to erase anything, thank you very much.
			tw.processFlush()
		} else {
			return false
		}
		return true
	case final == 'K': // Erase in Line
		if tw.line >= len(tw.lines) {
			return true
		}
		line := &tw.lines[tw.line]
		if len(params) == 0 || params[0] == 0 {
			if len(line.columns) > tw.column {
				line.columns = line.columns[:tw.column]
			}
		} else if params[0] == 1 {
			for i := 0; i < tw.column; i++ {
				line.columns[i] = ' '
			}
		} else if params[0] == 2 {
			line.columns = nil
		} else {
			return false
		}
		return true
	case final == 'm':
		// Straight up ignoring all attributes, at least for now.
		return true
	}
	return false
}

func (tw *terminalWriter) processCSI(rb []rune) ([]rune, bool) {
	if len(rb) < 3 {
		return nil, true
	}

	i, private, param, intermediate := 2, rune(0), []rune{}, []rune{}
	if rb[i] >= 0x3C && rb[i] <= 0x3F {
		private = rb[i]
		i++
	}
	for i < len(rb) && ((rb[i] >= '0' && rb[i] <= '9') || rb[i] == ';') {
		param = append(param, rb[i])
		i++
	}
	for i < len(rb) && rb[i] >= 0x20 && rb[i] <= 0x2F {
		intermediate = append(intermediate, rb[i])
		i++
	}
	if i == len(rb) {
		return nil, true
	}
	if rb[i] < 0x40 || rb[i] > 0x7E {
		return rb, false
	}
	if !tw.processParsedCSI(private, param, intermediate, rb[i]) {
		tw.log("unhandled CSI %s", string(rb[2:i+1]))
		return rb, false
	}
	return rb[i+1:], true
}

func (tw *terminalWriter) processEscape(rb []rune) ([]rune, bool) {
	if len(rb) < 2 {
		return nil, true
	}

	// Very roughly following https://vt100.net/emu/dec_ansi_parser
	// but being a bit stricter.
	switch r := rb[1]; {
	case r == '[':
		return tw.processCSI(rb)
	case r == ']':
		// TODO(p): Skip this properly, once we actually hit it.
		tw.log("unhandled OSC")
		return rb, false
	case r == 'P':
		// TODO(p): Skip this properly, once we actually hit it.
		tw.log("unhandled DCS")
		return rb, false

		// Only handling sequences we've seen bother us in real life.
	case r == 'c':
		// Full reset, use this to flush all output.
		tw.processFlush()
		return rb[2:], true
	case r == 'M':
		tw.line--
		return rb[2:], true

	case (r >= 0x30 && r <= 0x4F) || (r >= 0x51 && r <= 0x57) ||
		r == 0x59 || r == 0x5A || r == 0x5C || (r >= 0x60 && r <= 0x7E):
		// → esc_dispatch
		tw.log("unhandled ESC %c", r)
		return rb, false
		//return rb[2:], true
	case r >= 0x20 && r <= 0x2F:
		// → escape intermediate
		i := 2
		for i < len(rb) && rb[i] >= 0x20 && rb[i] <= 0x2F {
			i++
		}
		if i == len(rb) {
			return nil, true
		}
		if rb[i] < 0x30 || rb[i] > 0x7E {
			return rb, false
		}
		// → esc_dispatch
		tw.log("unhandled ESC %s", string(rb[1:i+1]))
		return rb, false
		//return rb[i+1:], true
	default:
		// Note that Debian 12 has been seen to produce ESC<U+2026>
		// and such due to some very blind string processing.
		return rb, false
	}
}

func (tw *terminalWriter) processRunes() bool {
	rb := tw.runeBuffer
	if len(rb) == 0 {
		return false
	}

	switch rb[0] {
	case '\a':
		// Ding dong!
	case '\b':
		if tw.column > 0 {
			tw.column--
		}
	case '\n', '\v':
		tw.line++

		// Forced ONLCR flag, because that's what most shell output expects.
		fallthrough
	case '\r':
		tw.column = 0

	case '\x1b':
		var ok bool
		if rb, ok = tw.processEscape(rb); rb == nil {
			return false
		} else if ok {
			tw.runeBuffer = rb
			return true
		}

		// Unsuccessful parses get printed for later inspection.
		fallthrough
	default:
		tw.processPrint(rb[0])
	}
	tw.runeBuffer = rb[1:]
	return true
}
