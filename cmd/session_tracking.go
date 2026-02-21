package cmd

import (
	"time"

	"github.com/aaearon/grant-cli/internal/cache"
)

// sessionTimestampRecorder records elevation timestamps. Package-level var for test injection.
var recordSessionTimestamp = func(sessionID string) {
	dir, err := cache.CacheDir()
	if err != nil {
		log.Info("failed to record session timestamp: %v", err)
		return
	}
	store := cache.NewStore(dir, 25*time.Hour)
	if err := cache.RecordSession(store, sessionID, time.Now()); err != nil {
		log.Info("failed to record session timestamp: %v", err)
	}
}
