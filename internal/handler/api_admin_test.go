package handler

import (
	"testing"
)

func TestParseLimitOffset(t *testing.T) {
	const def, max = 1000, 1000
	tests := []struct {
		name       string
		limit      string
		offset     string
		wantLimit  int
		wantOffset int
		wantErr    bool
	}{
		{"both empty uses defaults", "", "", def, 0, false},
		{"valid limit", "50", "", 50, 0, false},
		{"valid offset", "", "200", def, 200, false},
		{"both valid", "25", "75", 25, 75, false},
		{"limit at max", "1000", "", 1000, 0, false},
		{"limit above max clamps", "999999", "", max, 0, false},
		{"limit one", "1", "", 1, 0, false},
		{"offset zero", "", "0", def, 0, false},
		{"limit zero invalid", "0", "", 0, 0, true},
		{"limit negative invalid", "-5", "", 0, 0, true},
		{"limit non-numeric invalid", "abc", "", 0, 0, true},
		{"limit float invalid", "10.5", "", 0, 0, true},
		{"offset negative invalid", "", "-1", 0, 0, true},
		{"offset non-numeric invalid", "", "xyz", 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit, offset, err := parseLimitOffset(tt.limit, tt.offset, def, max)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseLimitOffset(%q, %q) error = %v, wantErr %v", tt.limit, tt.offset, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if limit != tt.wantLimit || offset != tt.wantOffset {
				t.Errorf("parseLimitOffset(%q, %q) = (%d, %d), want (%d, %d)",
					tt.limit, tt.offset, limit, offset, tt.wantLimit, tt.wantOffset)
			}
		})
	}
}
