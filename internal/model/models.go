package model

import (
	"encoding/json"
	"time"
)

// GetTimezone returns the user's timezone or empty string.
func (u *User) GetTimezone() string {
	if u.Timezone != nil {
		return *u.Timezone
	}
	return ""
}

type User struct {
	ID                 int              `json:"id"`
	Email              string           `json:"email"`
	PasswordHash       string           `json:"-"`
	DailyGoal          *int             `json:"daily_goal,omitempty"`
	TOTPSecret         *string          `json:"-"`
	TOTPEnabled        bool             `json:"totp_enabled"`
	EmailVerified      bool             `json:"email_verified"`
	CreatedAt          time.Time        `json:"created_at"`
	Timezone           *string          `json:"timezone"`
	WeightUnit         string           `json:"weight_unit"`
	TimezoneManual     bool             `json:"timezone_manual"`
	TodosEnabled       bool             `json:"todos_enabled"`
	NotesEnabled       bool             `json:"notes_enabled"`
	PreferredAIProvider *string         `json:"preferred_ai_provider"`
	AIKey              *string          `json:"-"`
	AIEndpoint         *string          `json:"ai_endpoint,omitempty"`
	AIModel            *string          `json:"ai_model,omitempty"`
	AIDailyLimit       *int             `json:"ai_daily_limit,omitempty"`
	AIKeyLast4         *string          `json:"ai_key_last4,omitempty"`
	MacrosEnabled      json.RawMessage  `json:"macros_enabled"`
	MacroGoals         json.RawMessage  `json:"macro_goals"`
	GoalThreshold      int              `json:"goal_threshold"`
}

type CalorieEntry struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	EntryDate string    `json:"entry_date"`
	Amount    int       `json:"amount"`
	EntryName *string   `json:"entry_name"`
	CreatedAt time.Time `json:"created_at"`
	ProteinG  *int      `json:"protein_g,omitempty"`
	CarbsG    *int      `json:"carbs_g,omitempty"`
	FatG      *int      `json:"fat_g,omitempty"`
	FiberG    *int      `json:"fiber_g,omitempty"`
	SugarG    *int      `json:"sugar_g,omitempty"`
}

type WeightEntry struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	EntryDate string    `json:"entry_date"`
	Weight    float64   `json:"weight"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AccountLink struct {
	ID             int       `json:"id"`
	RequesterID    int       `json:"requester_id"`
	TargetID       int       `json:"target_id"`
	Status         string    `json:"status"`
	RequesterLabel *string   `json:"requester_label,omitempty"`
	TargetLabel    *string   `json:"target_label,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Todo struct {
	ID         int             `json:"id"`
	UserID     int             `json:"user_id"`
	Name       string          `json:"name"`
	Schedule   json.RawMessage `json:"schedule"`
	TimeOfDay  *string         `json:"time_of_day"`
	SortOrder  int             `json:"sort_order"`
	Archived   bool            `json:"archived"`
	CreatedAt  time.Time       `json:"created_at"`
}

type TodoCompletion struct {
	ID             int    `json:"id"`
	TodoID         int    `json:"todo_id"`
	UserID         int    `json:"user_id"`
	CompletionDate string `json:"completion_date"`
}

type AdminSetting struct {
	Key       string    `json:"key"`
	Value     *string   `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

type MealTemplate struct {
	ID         int                `json:"id"`
	UserID     int                `json:"user_id"`
	Name       string             `json:"name"`
	IsFavorite bool               `json:"is_favorite"`
	SortOrder  int                `json:"sort_order"`
	CreatedAt  time.Time          `json:"created_at"`
	UpdatedAt  time.Time          `json:"updated_at"`
	Items      []MealTemplateItem `json:"items"`
}

type MealTemplateItem struct {
	ID         int     `json:"id"`
	TemplateID int     `json:"template_id"`
	EntryName  *string `json:"entry_name"`
	Amount     int     `json:"amount"`
	ProteinG   *int    `json:"protein_g,omitempty"`
	CarbsG     *int    `json:"carbs_g,omitempty"`
	FatG       *int    `json:"fat_g,omitempty"`
	FiberG     *int    `json:"fiber_g,omitempty"`
	SugarG     *int    `json:"sugar_g,omitempty"`
	SortOrder  int     `json:"sort_order"`
}
