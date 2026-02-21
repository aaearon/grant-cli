package cache

import "time"

// SessionRecord stores the timestamp when a session was elevated.
type SessionRecord struct {
	ElevatedAt time.Time `json:"elevated_at"`
}

const sessionTimestampsKey = "session_timestamps"

// maxSessionAge is the maximum age for session timestamp entries.
// Entries older than this are filtered out on read and removed on cleanup.
const maxSessionAge = 24 * time.Hour

// RecordSession stores the elevation timestamp for a session ID.
// It performs a read-modify-write on the session timestamps cache entry.
func RecordSession(s *Store, sessionID string, now time.Time) error {
	records := readRecords(s)
	records[sessionID] = SessionRecord{ElevatedAt: now}
	return Set(s, sessionTimestampsKey, records)
}

// SessionTimestamps returns a map of sessionID -> elevatedAt for all tracked sessions.
// Entries older than maxSessionAge are filtered out. Returns an empty map on error.
func SessionTimestamps(s *Store) map[string]time.Time {
	records := readRecords(s)
	now := s.now()
	result := make(map[string]time.Time, len(records))
	for id, rec := range records {
		if now.Sub(rec.ElevatedAt) <= maxSessionAge {
			result[id] = rec.ElevatedAt
		}
	}
	return result
}

// CleanupSessions removes entries for sessions not in the activeIDs list.
func CleanupSessions(s *Store, activeIDs []string) error {
	records := readRecords(s)
	if len(records) == 0 {
		return nil
	}

	active := make(map[string]bool, len(activeIDs))
	for _, id := range activeIDs {
		active[id] = true
	}

	changed := false
	for id := range records {
		if !active[id] {
			delete(records, id)
			changed = true
		}
	}

	if !changed {
		return nil
	}

	return Set(s, sessionTimestampsKey, records)
}

// readRecords reads the session timestamps cache entry. Returns an empty map on miss/error.
func readRecords(s *Store) map[string]SessionRecord {
	var records map[string]SessionRecord
	if Get(s, sessionTimestampsKey, &records) {
		return records
	}
	return make(map[string]SessionRecord)
}
