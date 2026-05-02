package session

import (
	"testing"
	"time"
)

func TestMarkStepUpStoresUnixSeconds(t *testing.T) {
	sess := &Session{Data: map[string]any{}}
	before := int(time.Now().Unix())
	sess.MarkStepUp()
	after := int(time.Now().Unix())

	ts, ok := sess.GetInt("step_up_at")
	if !ok {
		t.Fatal("step_up_at not stored")
	}
	if ts < before || ts > after {
		t.Errorf("step_up_at = %d, want between %d and %d", ts, before, after)
	}
	if !sess.dirty {
		t.Error("session should be dirty after MarkStepUp")
	}
}

func TestHasRecentStepUp(t *testing.T) {
	tests := []struct {
		name string
		data map[string]any
		want bool
	}{
		{"no step_up_at", map[string]any{}, false},
		{"just now", map[string]any{"step_up_at": int(time.Now().Unix())}, true},
		{"halfway through TTL", map[string]any{"step_up_at": int(time.Now().Add(-StepUpTTL / 2).Unix())}, true},
		{"just under TTL", map[string]any{"step_up_at": int(time.Now().Add(-(StepUpTTL - 1*time.Second)).Unix())}, true},
		{"exactly at TTL", map[string]any{"step_up_at": int(time.Now().Add(-StepUpTTL).Unix())}, false},
		{"well past TTL", map[string]any{"step_up_at": int(time.Now().Add(-StepUpTTL - 1*time.Hour).Unix())}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := &Session{Data: tt.data}
			if got := sess.HasRecentStepUp(); got != tt.want {
				t.Errorf("HasRecentStepUp() = %v, want %v", got, tt.want)
			}
		})
	}
}

// SetUserID should also mark step-up — every primary login completion
// implicitly elevates the session.
func TestSetUserIDMarksStepUp(t *testing.T) {
	sess := &Session{Data: map[string]any{}}
	sess.SetUserID(42)

	if !sess.HasRecentStepUp() {
		t.Error("SetUserID should also mark step-up")
	}
	if sess.MaxAge != AuthMaxAge {
		t.Errorf("MaxAge = %v, want %v", sess.MaxAge, AuthMaxAge)
	}
}
