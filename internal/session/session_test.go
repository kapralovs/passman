package session

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSession_SaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/session.json"

	original := &Session{
		Username:    "testuser",
		LastLoginAt: time.Now(),
		Trusted:     true,
	}

	err := Save(path, original)
	assert.NoError(t, err)

	loaded, err := Load(path)
	assert.NoError(t, err)

	assert.Equal(t, original.Username, loaded.Username)
	assert.Equal(t, original.Trusted, loaded.Trusted)
	assert.WithinDuration(t, original.LastLoginAt, loaded.LastLoginAt, time.Second)
}

func TestSession_LoadNonExistent(t *testing.T) {
	loaded, err := Load("/nonexistent/path/session.json")
	assert.NoError(t, err)
	assert.Empty(t, loaded.Username)
	assert.False(t, loaded.Trusted)
}

func TestSession_LoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/session.json"

	err := os.WriteFile(path, []byte("not json"), 0600)
	assert.NoError(t, err)

	_, err = Load(path)
	assert.Error(t, err)
}
