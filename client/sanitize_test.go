package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeStripsTerminalControls(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"hello", "hello"},
		{"привет мир", "привет мир"},               // UTF-8 preserved
		{"\x1b[2Jcleared", "[2Jcleared"},           // ESC dropped: sequence can no longer execute
		{"a\nb\rc\td", "a b c d"},                  // whitespace flattened
		{"no\x00nulls\x07", "nonulls"},             // NUL and BEL dropped
		{"c1:\u0085gone", "c1:gone"},               // C1 control dropped
		{"evil\u202etxet\u2066rev", "eviltxetrev"}, // BiDi overrides dropped
		{"\ufeffhidden", "hidden"},                 // BOM dropped
		{"\x1b]0;title\x07after", "]0;titleafter"}, // OSC sequence neutralized
	}
	for _, c := range cases {
		if got := sanitize(c.in, 100); got != c.want {
			t.Errorf("sanitize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeCapsLength(t *testing.T) {
	in := strings.Repeat("ab", 5000) // 10000 runes
	got := sanitize(in, 50)
	if n := utf8.RuneCountInString(got); n != 50 {
		t.Fatalf("expected exactly 50 runes, got %d", n)
	}
}

func TestSanitizeEmpty(t *testing.T) {
	if got := sanitize("", 10); got != "" {
		t.Fatalf("want empty, got %q", got)
	}
}
