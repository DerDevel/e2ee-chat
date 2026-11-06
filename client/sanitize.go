package main

import "strings"

const (
	maxNickRunes = 32
	maxTextRunes = 2000
)

// sanitize strips everything that could hijack the terminal from a
// peer-controlled string before it is rendered: control characters (which
// include the ESC that introduces ANSI escape sequences), C1 controls that
// some terminals interpret even when arriving as UTF-8, and bidirectional
// text overrides used to disguise message content. Newlines and tabs become
// spaces, and the result is capped at max runes.
func sanitize(s string, max int) string {
	var b strings.Builder
	b.Grow(min(len(s), max*4))
	n := 0
	for _, r := range s {
		if n == max {
			break
		}
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteRune(' ')
			n++
		case r < 0x20, r == 0x7f:
			// C0 controls — dropped, including ESC.
		case r >= 0x80 && r <= 0x9f:
			// C1 controls.
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			// BiDi overrides.
		case r == 0xfeff:
			// Zero-width no-break space (BOM spoofing).
		case r == 0x200b, r == 0x200c, r == 0x200d, r == 0x2060, r == 0x180e, r == 0xad:
			// Zero-width joiners/characters and the soft hyphen: invisible
			// content spoofing ("identical-looking" messages).
		case r == 0x2028, r == 0x2029:
			// Line/paragraph separators.
		default:
			b.WriteRune(r)
			n++
		}
	}
	return b.String()
}
