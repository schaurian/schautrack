package handler

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// The entry form validates calories and macros in the browser so it can mark
// the offending field inline instead of round-tripping to a toast. That only
// works while the client's bounds are the server's: a client bound looser than
// MaxEntryCalories / MaxEntryMacro lets a value through that CreateEntry then
// rejects with a message the form can only show as a toast, and a tighter one
// refuses a value the server would have stored.
func TestClientEntryLimitsMatchServer(t *testing.T) {
	path := filepath.Join("..", "..", "client", "src", "lib", "entryValidation.ts")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for name, want := range map[string]int{
		"MAX_ENTRY_CALORIES": MaxEntryCalories,
		"MAX_ENTRY_MACRO":    MaxEntryMacro,
	} {
		m := regexp.MustCompile(`export const ` + name + ` = (\d+);`).FindSubmatch(src)
		if m == nil {
			t.Errorf("%s: no `export const %s = <int>;` found", path, name)
			continue
		}
		got, _ := strconv.Atoi(string(m[1]))
		if got != want {
			t.Errorf("%s = %d in %s, but the server enforces %d", name, got, path, want)
		}
	}
}
