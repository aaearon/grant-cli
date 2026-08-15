package cache

import "time"

// SessionRecord stores the timestamp when a session was elevated.
type SessionRecord struct {
	ElevatedAt time.Time `json:"elevated_at"`
}

const sessionTimestampsKey = "session_timestamps"

// sessionTimestampRetention is how long a locally recorded elevation timestamp
// stays useful. Entries older than this are filtered out by SessionTimestamps.
//
// It is purely local retention for the remaining-time DISPLAY. It is not a
// session lifetime, not a session limit, and not an access-control boundary:
// dropping a timestamp only removes grant's ability to show how long a session
// has left, and has no effect on the session itself. CleanupSessions does not
// read this constant at all — it filters on activeIDs membership only.
const sessionTimestampRetention = 24 * time.Hour

// RecordSession stores the elevation timestamp for a session ID.
// It performs a read-modify-write on the session timestamps cache entry.
func RecordSession(s *Store, sessionID string, now time.Time) error {
	records := readRecords(s)
	records[sessionID] = SessionRecord{ElevatedAt: now}
	return Set(s, sessionTimestampsKey, records)
}

// SessionTimestamps returns a map of sessionID -> elevatedAt for all tracked sessions.
// Entries older than sessionTimestampRetention are filtered out. Returns an empty map on error.
func SessionTimestamps(s *Store) map[string]time.Time {
	records := readRecords(s)
	now := s.now()
	result := make(map[string]time.Time, len(records))
	for id, rec := range records {
		if now.Sub(rec.ElevatedAt) <= sessionTimestampRetention {
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
