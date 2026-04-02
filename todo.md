# Schautrack TODO

### 1. Undo on delete
- Entries/weight/todos delete instantly with no way back. Add a short undo toast (3-4s) before the actual deletion.

### 2. Weight chart
- Weight entries have no trend visualization. Add a sparkline or line chart to show progress over time.

### 3. Lazy loading routes
- All pages bundled together. Wrap routes in `React.lazy` to improve initial load time on mobile.

### 4. Fix MaxLinks in CLAUDE.md
- CLAUDE.md says max 3 linked accounts, actual constant is 10.

---

## Maybe

### 5. Meal categories
- Group entries by breakfast/lunch/dinner/snack for easier scanning.

### 6. Favorites / recent foods
- Quick-add from recently logged entries to save repetitive typing.

### 7. Calorie goal streak
- Todos have streaks but the main calorie goal doesn't. A streak counter on the dashboard would be motivating.

### 8. CSV export
- Only JSON supported. CSV would be useful for spreadsheet analysis.
